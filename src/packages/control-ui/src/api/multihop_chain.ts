export interface RelayHop {
  hopIndex: number;
  endpoint: string;
  publicKey: string;
}

export class MultihopRelayChain {
  constructor(
    public readonly entryHop: RelayHop,
    public readonly exitHop: RelayHop,
    public readonly quantumResistantPsk: Uint8Array
  ) {}

  public getNestedAllowedIps(): [string, string] {
    return ['10.64.0.1/32', '0.0.0.0/0, ::/0'];
  }
}
