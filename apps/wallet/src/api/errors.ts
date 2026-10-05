export class NodeApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly retryable: boolean;

  constructor(
    message: string,
    status: number,
    code = "node_request_failed",
    retryable = false,
  ) {
    super(message);
    this.name = "NodeApiError";
    this.status = status;
    this.code = code;
    this.retryable = retryable;
  }
}
