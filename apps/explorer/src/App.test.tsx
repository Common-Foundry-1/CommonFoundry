import { render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import App from "./App";

vi.mock("./api", async () => {
  const { demoSnapshot } = await import("./demoData");
  return { loadExplorer: vi.fn().mockResolvedValue({ data: demoSnapshot, preview: true }), loadBlock: vi.fn(), loadTransaction: vi.fn() };
});

test("renders the branded explorer overview", async () => {
  render(<App />);
  expect(await screen.findByRole("heading", { name: "The chain, as it happens." })).toBeInTheDocument();
  expect(screen.getByRole("heading", { name: "Latest blocks" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /pause/i })).toBeInTheDocument();
});
