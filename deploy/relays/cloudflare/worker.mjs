import bpbWorker from "./bpb_worker.js";
import gsaRelayWorker from "../cloudflare_worker.js";
import zeusWorker from "./zeus_worker.js";
import { stripRoutePrefix } from "./worker_contract.mjs";

export async function handleWorkerRequest(request, env, ctx) {
  const bpbRequest = stripRoutePrefix(request, "/bpb");
  if (bpbRequest) {
    return bpbWorker.fetch(bpbRequest, env, ctx);
  }
  const relayRequest = stripRoutePrefix(request, "/relay");
  if (relayRequest) {
    return gsaRelayWorker.fetch(relayRequest, env, ctx);
  }
  return zeusWorker.fetch(request, env, ctx);
}

export default {
  fetch: handleWorkerRequest,
};
