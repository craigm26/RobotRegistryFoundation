import { describe, it, expect } from "vitest";
import { presentAssurance, validateAssurance, pickAssurance, ASSURANCE_NOTE } from "./assurance.js";

const HASH = "sha256:" + "ab".repeat(32);
const URL_OK = "https://lab.example/report.pdf";

describe("validateAssurance", () => {
  it("accepts a record with no assurance fields", () => expect(validateAssurance({})).toBeNull());
  it("accepts A1 and A2 without evidence", () => {
    expect(validateAssurance({ assurance_level: "A1" })).toBeNull();
    expect(validateAssurance({ assurance_level: "A2", envelope_hash: HASH })).toBeNull();
  });
  it("rejects an RCAN L-level in the assurance field", () => {
    expect(validateAssurance({ assurance_level: "L3" })).toMatch(/not an RCAN L-level/);
  });
  it("rejects A3 without an evidence URL", () => {
    expect(validateAssurance({ assurance_level: "A3" })).toMatch(/requires assurance_evidence_url/);
  });
  it("accepts A3 with an https evidence URL", () => {
    expect(validateAssurance({ assurance_level: "A3", assurance_evidence_url: URL_OK })).toBeNull();
  });
  it("rejects non-https evidence URLs", () => {
    for (const u of ["http://lab.example/r", "javascript:alert(1)", "not a url"]) {
      expect(validateAssurance({ assurance_level: "A3", assurance_evidence_url: u }), u).toMatch(/https/);
    }
  });
  it("rejects a malformed envelope hash", () => {
    expect(validateAssurance({ assurance_level: "A1", envelope_hash: "sha256:XYZ" })).toMatch(/envelope_hash/);
  });
  it("rejects evidence or hash without a level", () => {
    expect(validateAssurance({ envelope_hash: HASH })).toMatch(/require assurance_level/);
  });
});

describe("presentAssurance", () => {
  it("returns null when no level is declared", () => expect(presentAssurance({})).toBeNull());

  it("labels A1 and A2 as self-declared", () => {
    for (const lvl of ["A1", "A2"]) {
      const v = presentAssurance({ assurance_level: lvl })!;
      expect(v.level).toBe(lvl);
      expect(v.basis).toBe("self-declared");
      expect(v.displayed).toBe(true);
      expect(v.note).toBe(ASSURANCE_NOTE);
    }
  });

  it("A2 with evidence is still self-declared, with evidence linked", () => {
    const v = presentAssurance({ assurance_level: "A2", assurance_evidence_url: URL_OK })!;
    expect(v.basis).toBe("self-declared, third-party evidence linked");
  });

  it("A3 displays only with a third-party evidence URL", () => {
    const shown = presentAssurance({ assurance_level: "A3", assurance_evidence_url: URL_OK })!;
    expect(shown.level).toBe("A3");
    expect(shown.displayed).toBe(true);

    // A record stored before validation existed, or edited out of band.
    const hidden = presentAssurance({ assurance_level: "A3" })!;
    expect(hidden.level).toBeNull();
    expect(hidden.claimed_level).toBe("A3");
    expect(hidden.displayed).toBe(false);
    expect(hidden.reason_not_displayed).toMatch(/third-party evidence URL/);
  });

  it("never claims RRF verified anything", () => {
    const v = presentAssurance({ assurance_level: "A3", assurance_evidence_url: URL_OK })!;
    expect(JSON.stringify(v)).not.toMatch(/"verified"|certified by RRF/i);
    expect(v.note).toMatch(/RRF does not test robots/);
    expect(v.note).toMatch(/Conformance is not certification/);
  });

  it("drops an unsafe stored URL from the view", () => {
    const v = presentAssurance({ assurance_level: "A3", assurance_evidence_url: "javascript:alert(1)" })!;
    expect(v.evidence_url).toBeNull();
    expect(v.displayed).toBe(false);
  });
});

describe("pickAssurance", () => {
  it("picks only the assurance fields", () => {
    expect(pickAssurance({ name: "x", assurance_level: "A1", envelope_hash: null }))
      .toEqual({ assurance_level: "A1", envelope_hash: null });
  });
});
