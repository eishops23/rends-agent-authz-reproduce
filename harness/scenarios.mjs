// The four scenarios, defined once and consumed by every stack.
// Changing a scenario here changes it for all stacks — that is intentional.

export const AGENT_PRINCIPAL = "agent://treasury-ops/v1";
export const DELEGATED_HUMAN = "alice@examplebank.com";

export const SCENARIOS = [
  {
    id: "S1",
    label: "ALLOW",
    args: { from: "ACCT-A", to: "ACCT-B", amount: 8000.0, currency: "USD" },
    expect: { decision: "ALLOW", sideEffect: true },
  },
  {
    id: "S2",
    label: "ESCALATE",
    args: { from: "ACCT-A", to: "ACCT-B", amount: 27500.0, currency: "USD" },
    expect: { decision: "ESCALATE", sideEffect: true, approvalRequiredBefore: true },
  },
  {
    id: "S3",
    label: "DENY",
    args: { from: "ACCT-A", to: "ACCT-SANCTIONED-9", amount: 27500.0, currency: "USD" },
    expect: { decision: "DENY", sideEffect: false },
  },
];

/** The policy of POLICY-SPEC.md, as a plain decision function. */
export function decide({ to, amount }) {
  if (to === "ACCT-SANCTIONED-9") return { decision: "DENY", clause: "C3" };
  if (amount <= 10000.0) return { decision: "ALLOW", clause: "C1" };
  if (amount <= 50000.0) return { decision: "ESCALATE", clause: "C2" };
  return { decision: "DENY", clause: "default-deny" };
}
