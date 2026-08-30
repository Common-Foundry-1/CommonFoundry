import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
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

test("pauses and resumes the forge cycle", async () => {
  const user = userEvent.setup();
  const view = render(<App />);
  const explorer = within(view.container);

  const pause = await explorer.findByRole("button", { name: "Pause" });
  await user.click(pause);
  expect(explorer.getByRole("button", { name: "Resume" })).toHaveAttribute("aria-pressed", "true");
  expect(explorer.getByRole("region", { name: "Live transaction forging visualization" })).toHaveClass("is-paused");

  await user.click(explorer.getByRole("button", { name: "Resume" }));
  expect(explorer.getByRole("button", { name: "Pause" })).toHaveAttribute("aria-pressed", "false");
});
