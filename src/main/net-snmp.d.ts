/**
 * net-snmp 库的类型声明
 * 官方未提供 @types/net-snmp，这里手动声明常用 API
 */
declare module 'net-snmp' {
  export interface SessionOptions {
    port?: number;
    retries?: number;
    timeout?: number;
    transport?: string;
    version?: number;
    community?: string;
    disableAuthorization?: boolean;
  }

  export interface Varbind {
    oid: string;
    type: number;
    value: any;
  }

  export interface TrapPdu {
    version?: number;
    type?: number;
    enterprise?: string;
    agentAddr?: string;
    varbinds: Varbind[];
  }

  export interface Trap {
    pdu?: TrapPdu;
    varbinds?: Varbind[];
    rinfo?: {
      address: string;
      port: number;
    };
  }

  export class Session {
    constructor(target: string, community?: string, options?: SessionOptions);
    get(oids: string[], callback: (error: Error | null, varbinds: Varbind[]) => void): void;
    getNext(oids: string[], callback: (error: Error | null, varbinds: Varbind[]) => void): void;
    subtree(
      oid: string,
      maxRepetitions: number,
      feedCb: (varbinds: Varbind[]) => void,
      doneCb?: (error: Error | null) => void
    ): void;
    set(oids: string[], callback: (error: Error | null, varbinds: Varbind[]) => void): void;
    table(
      oid: string,
      maxRepetitions: number,
      callback: (error: Error | null, table: Record<string, Record<string, any>>) => void
    ): void;
    tableColumns(
      oid: string,
      columns: number[],
      maxRepetitions: number,
      callback: (error: Error | null, table: Record<string, Record<string, any>>) => void
    ): void;
    close(): void;
  }

  export const Version1: number;
  export const Version2c: number;
  export const Version3: number;

  /** SNMPv3 安全级别 */
  export const SecurityLevel: {
    noAuthNoPriv: number;
    authNoPriv: number;
    authPriv: number;
  };

  /** SNMPv3 认证协议 */
  export const AuthProtocols: {
    none: number;
    md5: number;
    sha: number;
    sha224: number;
    sha256: number;
    sha384: number;
    sha512: number;
  };

  /** SNMPv3 加密协议 */
  export const PrivProtocols: {
    none: number;
    des: number;
    aes: number;
    aes256b: number;
    aes256r: number;
  };

  export interface V3User {
    name: string;
    level?: number;
    authProtocol?: number;
    authKey?: string;
    privProtocol?: number;
    privKey?: string;
  }

  export interface V3SessionOptions extends SessionOptions {
    timeouts?: number[];
    idBits?: number;
    msgMaxSize?: number;
    contextName?: string;
    engineID?: string | Buffer;
  }

  export function createSession(
    target: string,
    community?: string,
    options?: SessionOptions
  ): Session;

  export function createV3Session(
    target: string,
    user: V3User,
    options?: V3SessionOptions
  ): Session;

  export interface Receiver {
    close(): void;
  }

  export function createReceiver(
    options: SessionOptions,
    callback: (error: Error | null, trap: Trap) => void
  ): Receiver;
}
