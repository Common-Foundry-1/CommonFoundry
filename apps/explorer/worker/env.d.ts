interface Env {
  ASSETS: {
    fetch(request: Request): Promise<Response>;
  };
  EXPLORER_ORIGIN: string;
}

interface ExportedHandler<Bindings> {
  fetch(request: Request, env: Bindings): Response | Promise<Response>;
}
