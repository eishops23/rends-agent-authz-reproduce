// L2 tool target — `transfer_funds`, behind the AgentCore Gateway.
//
// ⛔ THE TOOL HAS NO AUTHORIZATION LOGIC OF ITS OWN. That is the whole design:
// harness/ledger.mjs says the same thing for L1/L4. Whether this code runs is
// the control question, and each stack answers it differently.
//
// ⭐ L2's LEDGER IS THIS FUNCTION'S INVOCATION RECORD, not a JSON file.
// Axis 3 asks whether there is PROOF a denied side effect never occurred. For
// L1/L4 that proof is a ledger file the operator also controls. Here the proof
// is whether the Lambda ran at all — CloudWatch Invocations plus the EXECUTED
// line below. ⚠️ That is a DIFFERENT KIND of evidence and the artifact must say
// so rather than presenting it as the same measurement: it is stronger in that
// the tool cannot be reached without the gateway invoking it, and weaker in
// that it is retained by the same operator who holds everything else in L2.

export const handler = async (event) => {
  const args = event?.arguments ?? event?.input ?? event ?? {};
  const { from, to, amount, currency } = args;

  // Structured so a grep for EXECUTED over the log group is a clean
  // "did the side effect happen" instrument for every scenario.
  console.log(JSON.stringify({
    marker: "EXECUTED",
    tool: "transfer_funds",
    from, to, amount, currency,
    at: new Date().toISOString(),
  }));

  return {
    executed: true,
    from, to, amount, currency,
    // Deliberately NOT a running balance: the function is stateless and a
    // fabricated balance would be an assertion dressed as a fact.
    note: "side effect recorded in CloudWatch Logs; see marker=EXECUTED",
  };
};
