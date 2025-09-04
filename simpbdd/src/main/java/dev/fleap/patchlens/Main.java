package dev.fleap.patchlens;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.fasterxml.jackson.core.JsonParseException;
import com.github.javabdd.BDD;
import com.github.javabdd.BDDFactory;
import com.github.javabdd.JFactory;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public final class Main {

    // AST of the Flag enum from Patchlens
    public interface Flag {
    }

    public static final class TrueFlag implements Flag {
        public String toString() {
            return "True";
        }
    }

    public static final class FalseFlag implements Flag {
        public String toString() {
            return "False";
        }
    }

    public static final class BuildingFlag implements Flag {
        public final String name;

        public BuildingFlag(String n) {
            this.name = n;
        }

        public String toString() {
            return "Building(" + name + ")";
        }
    }

    public static final class DefinedFlag implements Flag {
        public final String name;

        public DefinedFlag(String n) {
            this.name = n;
        }

        public String toString() {
            return "Defined(" + name + ")";
        }
    }

    public static final class NotFlag implements Flag {
        public final Flag inner;

        public NotFlag(Flag f) {
            this.inner = f;
        }

        public String toString() {
            return "Not(" + inner + ")";
        }
    }

    public static final class AndFlag implements Flag {
        public final List<Flag> terms;

        public AndFlag(List<Flag> ts) {
            this.terms = ts;
        }

        public String toString() {
            return "And" + terms;
        }
    }

    public static final class OrFlag implements Flag {
        public final List<Flag> terms;

        public OrFlag(List<Flag> ts) {
            this.terms = ts;
        }

        public String toString() {
            return "Or" + terms;
        }
    }

    public static final class EqualFlag implements Flag {
        public final String left, right;

        public EqualFlag(String l, String r) {
            left = l;
            right = r;
        }

        public String toString() {
            return "Equal(" + left + "," + right + ")";
        }
    }

    // JSON IO
    static final class FlagJsonParser {
        private static final ObjectMapper M = new ObjectMapper();

        public Flag parse(InputStream in) throws IOException {
            return parseNode(M.readTree(in));
        }

        public Flag parseString(String s) throws IOException {
            return parseNode(M.readTree(s));
        }

        private Flag parseNode(JsonNode node) throws IOException {
            if (node == null || node.isNull()) throw new JsonParseException(null, "Expected Flag, found null");

            if (node.isTextual()) {
                return switch (node.asText()) {
                    case "True" -> new TrueFlag();
                    case "False" -> new FalseFlag();
                    default -> throw new JsonParseException(null, "Unknown unit variant: " + node.asText());
                };
            }

            if (node.isObject()) {
                Iterator<String> it = node.fieldNames();
                if (!it.hasNext()) throw new JsonParseException(null, "Empty object is not a valid Flag");
                String tag = it.next();
                if (it.hasNext()) throw new JsonParseException(null, "Expected single-key enum object");
                JsonNode payload = node.get(tag);

                switch (tag) {
                    case "True":
                        return new TrueFlag();
                    case "False":
                        return new FalseFlag();
                    case "Building":
                        if (!payload.isTextual()) throw new JsonParseException(null, "Building expects string");
                        return new BuildingFlag(payload.asText());
                    case "Defined":
                        if (!payload.isTextual()) throw new JsonParseException(null, "Defined expects string");
                        return new DefinedFlag(payload.asText());
                    case "Not":
                        return new NotFlag(parseNode(payload));
                    case "And":
                        return new AndFlag(parseArrayOfFlags("And", payload));
                    case "Or":
                        return new OrFlag(parseArrayOfFlags("Or", payload));
                    case "Equal":
                        if (!payload.isArray() || payload.size() != 2
                                || !payload.get(0).isTextual() || !payload.get(1).isTextual())
                            throw new JsonParseException(null, "Equal expects [string, string]");
                        return new EqualFlag(payload.get(0).asText(), payload.get(1).asText());
                    default:
                        throw new JsonParseException(null, "Unknown variant: " + tag);
                }
            }

            if (node.isArray()) throw new JsonParseException(null, "Top-level array is not a valid Flag");
            throw new JsonParseException(null, "Unsupported JSON for Flag: " + node);
        }

        private List<Flag> parseArrayOfFlags(String variant, JsonNode arr) throws IOException {
            if (!arr.isArray()) throw new JsonParseException(null, variant + " expects array");
            List<Flag> out = new ArrayList<>(arr.size());
            for (JsonNode e : arr) out.add(parseNode(e));
            return out;
        }
    }

    static final class FlagJsonIO {
        static final ObjectMapper M = new ObjectMapper();

        static JsonNode toJsonNode(Flag f) {
            if (f instanceof TrueFlag) return TextNode.valueOf("True");
            if (f instanceof FalseFlag) return TextNode.valueOf("False");

            if (f instanceof DefinedFlag d) {
                ObjectNode o = M.createObjectNode();
                o.set("Defined", TextNode.valueOf(d.name));
                return o;
            }
            if (f instanceof BuildingFlag b) {
                ObjectNode o = M.createObjectNode();
                o.set("Building", TextNode.valueOf(b.name));
                return o;
            }
            if (f instanceof NotFlag n) {
                ObjectNode o = M.createObjectNode();
                o.set("Not", toJsonNode(n.inner));
                return o;
            }
            if (f instanceof AndFlag a) {
                ObjectNode o = M.createObjectNode();
                ArrayNode arr = M.createArrayNode();
                for (Flag t : a.terms) arr.add(toJsonNode(t));
                o.set("And", arr);
                return o;
            }
            if (f instanceof OrFlag or) {
                ObjectNode o = M.createObjectNode();
                ArrayNode arr = M.createArrayNode();
                for (Flag t : or.terms) arr.add(toJsonNode(t));
                o.set("Or", arr);
                return o;
            }
            if (f instanceof EqualFlag eq) {
                ObjectNode o = M.createObjectNode();
                ArrayNode arr = M.createArrayNode();
                arr.add(TextNode.valueOf(eq.left));
                arr.add(TextNode.valueOf(eq.right));
                o.set("Equal", arr);
                return o;
            }
            throw new IllegalArgumentException("Unknown Flag: " + f);
        }
    }

    // BDD env + builder
    static final class BddEnv implements Closeable {
        private final BDDFactory f;
        private final Map<String, Integer> nameToIdx = new LinkedHashMap<>();
        private final List<String> idxToName = new ArrayList<>();

        BddEnv(int nodes, int cache) {
            this.f = JFactory.init(nodes, cache);
            if (f.varNum() == 0) f.setVarNum(1); // seed; we only ever INCREASE afterwards
        }

        public BDDFactory factory() {
            return f;
        }

        public BDD var(String name) {
            Integer idx = nameToIdx.get(name);
            if (idx == null) {
                idx = nameToIdx.size();
                nameToIdx.put(name, idx);
                ensureVarCount(idx + 1);
                // grow reverse map
                while (idxToName.size() <= idx) idxToName.add(null);
                idxToName.set(idx, name);
            }
            return f.ithVar(idx);
        }

        public String varName(int idx) {
            if (idx < 0 || idx >= idxToName.size()) return null;
            return idxToName.get(idx);
        }

        public int varCount() {
            return nameToIdx.size();
        }

        public List<String> varOrder() {
            return new ArrayList<>(nameToIdx.keySet());
        }

        private void ensureVarCount(int n) {
            if (f.varNum() < n) f.setVarNum(n);
        }

        @Override
        public void close() { /* no-op */ }
    }

    static final class BddBuilder {
        private final BddEnv env;

        BddBuilder(BddEnv env) {
            this.env = env;
        }

        public BDD build(Flag flag) {
            if (flag instanceof TrueFlag) return env.factory().one();
            if (flag instanceof FalseFlag) return env.factory().zero();

            if (flag instanceof DefinedFlag d) return env.var("DEF::" + d.name);
            if (flag instanceof BuildingFlag b) return env.var("BUILD::" + b.name);

            if (flag instanceof NotFlag n) return build(n.inner).not();

            if (flag instanceof AndFlag a) {
                BDD acc = env.factory().one();
                for (Flag t : a.terms) {
                    BDD next = build(t);
                    BDD tmp = acc.and(next);
                    acc.free();
                    next.free();
                    acc = tmp;
                }
                return acc;
            }

            if (flag instanceof OrFlag o) {
                BDD acc = env.factory().zero();
                for (Flag t : o.terms) {
                    BDD next = build(t);
                    BDD tmp = acc.or(next);
                    acc.free();
                    next.free();
                    acc = tmp;
                }
                return acc;
            }

            if (flag instanceof EqualFlag e) {
                BDD a = env.var("DEF::" + e.left);
                BDD b = env.var("DEF::" + e.right);
                return a.biimp(b);
            }

            throw new IllegalArgumentException("Unknown Flag impl: " + flag.getClass());
        }
    }

    // simpBDD
    public static BDD simpBDD(BDD p, BDD m) {
        return p.constrain(m);
    }

    // BDD -> Flag reconstruction
    static final class FromBdd {
        private final BddEnv env;

        FromBdd(BddEnv env) {
            this.env = env;
        }

        public Flag toFlag(BDD u) {
            // Terminal cases
            if (u.isOne()) return new TrueFlag();
            if (u.isZero()) return new FalseFlag();

            int varIdx = u.var();
            String name = env.varName(varIdx);
            Flag varF = nameToFlag(name);

            // Shannon expansion: u = (v & high) | (!v & low)
            BDD hi = u.high();
            BDD lo = u.low();

            Flag t = toFlag(hi);
            Flag e = toFlag(lo);

            hi.free();
            lo.free();

            // Simple algebraic collapses
            if (t instanceof TrueFlag && e instanceof FalseFlag) return varF;             // v
            if (t instanceof FalseFlag && e instanceof TrueFlag) return not(varF);        // !v
            if (eq(t, e)) return t;                // (v&x)|(!v&x) == x

            // General case: (v ∧ t) ∨ (¬v ∧ e)
            return or(and(varF, t), and(not(varF), e));
        }

        private Flag nameToFlag(String enc) {
            if (enc == null) return new FalseFlag();
            if (enc.startsWith("DEF::")) return new DefinedFlag(enc.substring("DEF::".length()));
            if (enc.startsWith("BUILD::")) return new BuildingFlag(enc.substring("BUILD::".length()));
            // fallback
            return new DefinedFlag(enc);
        }

        // ---- tiny normalizers: flatten + remove neutral/absorbing elements ----
        private Flag and(Flag a, Flag b) {
            return and(List.of(a, b));
        }

        private Flag or(Flag a, Flag b) {
            return or(List.of(a, b));
        }

        private Flag not(Flag f) {
            if (f instanceof TrueFlag) return new FalseFlag();
            if (f instanceof FalseFlag) return new TrueFlag();
            if (f instanceof NotFlag n) return n.inner; // !!x = x
            return new NotFlag(f);
        }

        private Flag and(List<Flag> items) {
            ArrayList<Flag> flat = new ArrayList<>();
            for (Flag f : items) {
                if (f instanceof FalseFlag) return new FalseFlag();
                if (f instanceof TrueFlag) continue;
                if (f instanceof AndFlag a) flat.addAll(a.terms);
                else flat.add(f);
            }
            if (flat.isEmpty()) return new TrueFlag();
            if (flat.size() == 1) return flat.get(0);
            return new AndFlag(flat);
        }

        private Flag or(List<Flag> items) {
            ArrayList<Flag> flat = new ArrayList<>();
            for (Flag f : items) {
                if (f instanceof TrueFlag) return new TrueFlag();
                if (f instanceof FalseFlag) continue;
                if (f instanceof OrFlag o) flat.addAll(o.terms);
                else flat.add(f);
            }
            if (flat.isEmpty()) return new FalseFlag();
            if (flat.size() == 1) return flat.get(0);
            return new OrFlag(flat);
        }

        private boolean eq(Flag a, Flag b) {
            // cheap structural eq by toString (good enough for light dedup during rebuild)
            return Objects.equals(a.toString(), b.toString());
        }
    }

    // CLI
    public static void main(String[] args) throws Exception {
        String contextJsonInline = null;
        Path contextPath = null;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--context":
                    if (++i >= args.length) die("Missing value for --context");
                    contextPath = Path.of(args[i]);
                    break;
                case "--context-json":
                    if (++i >= args.length) die("Missing value for --context-json");
                    contextJsonInline = args[i];
                    break;
                default:
                    die("Unknown arg: " + args[i]);
            }
        }
        if (contextJsonInline != null && contextPath != null) die("Use either --context or --context-json, not both.");

        FlagJsonParser parser = new FlagJsonParser();

        Flag pFlag = parser.parse(System.in);

        Flag mFlag;
        if (contextJsonInline != null) {
            mFlag = parser.parseString(contextJsonInline);
        } else if (contextPath != null) {
            try (InputStream in = Files.newInputStream(contextPath)) {
                mFlag = parser.parse(in);
            }
        } else {
            mFlag = new TrueFlag();
        }

        try (BddEnv env = new BddEnv(3_000_000, 500_000)) {
            BddBuilder builder = new BddBuilder(env);
            BDD p = builder.build(pFlag);
            BDD m = builder.build(mFlag);
            BDD s = simpBDD(p, m);

            BDD okBDD = m.imp(s.biimp(p));
            boolean ok = okBDD.isOne();

            FromBdd rebuilder = new FromBdd(env);
            Flag simplified = rebuilder.toFlag(s);
            JsonNode outJson = FlagJsonIO.toJsonNode(simplified);

            System.out.println(FlagJsonIO.M.writeValueAsString(outJson));

            System.err.println("Variables: " + env.varCount() + " " + env.varOrder());
            System.err.println("Equivalent under m? " + ok);
            System.err.println("Node count (p): " + p.nodeCount());
            System.err.println("Node count (m): " + m.nodeCount());
            System.err.println("Node count (simpBDD): " + s.nodeCount());

            okBDD.free();
            s.free();
            p.free();
            m.free();
        }
    }

    private static void die(String msg) {
        System.err.println(msg);
        System.exit(2);
    }
}

