import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import App from "./App";
import { loadExplorer, type ExplorerLoad } from "./api";
import { demoSnapshot } from "./demoData";

vi.mock("./api", async () => {
  const { demoSnapshot } = await import("./demoData");
  return { MAINNET_MODE: false, loadExplorer: vi.fn().mockResolvedValue({ data: demoSnapshot, preview: true }), loadBlock: vi.fn(), loadTransaction: vi.fn() };
});

beforeEach(() => vi.mocked(loadExplorer).mockReset().mockResolvedValue({ data: demoSnapshot, preview: true }));
afterEach(() => vi.restoreAllMocks());

function capturePoll() {
  let poll: (() => void) | undefined;
  const original = window.setInterval.bind(window);
  vi.spyOn(window, "setInterval").mockImplementation((handler, delay) => {
    if (delay === 10_000 && typeof handler === "function") { poll = () => handler(); return -1; }
    return original(handler, delay);
  });
  return () => { if (!poll) throw new Error("Refresh interval missing"); poll(); };
}

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

test("removes stale live data on a failed refresh and recovers through Retry", async () => {
  const poll = capturePoll();
  vi.mocked(loadExplorer).mockResolvedValueOnce({ data: demoSnapshot, preview: false })
    .mockRejectedValueOnce(new Error("network identity rejected"));
  render(<App />);
  expect(await screen.findByRole("heading", { name: "The chain, as it happens." })).toBeInTheDocument();
  await act(async () => { poll(); });
  expect(await screen.findByText("Explorer unavailable")).toBeInTheDocument();
  expect(screen.queryByRole("heading", { name: "Latest blocks" })).not.toBeInTheDocument();
  await userEvent.setup().click(screen.getByRole("button", { name: "Retry" }));
  expect(await screen.findByRole("heading", { name: "Latest blocks" })).toBeInTheDocument();
});

test("an older response cannot overwrite a newer connection failure", async () => {
  const poll = capturePoll();
  let resolveEarlier: ((value: ExplorerLoad) => void) | undefined;
  const earlier = new Promise<ExplorerLoad>((resolve) => { resolveEarlier = resolve; });
  vi.mocked(loadExplorer).mockRejectedValueOnce(new Error("initially offline"))
    .mockReturnValueOnce(earlier).mockRejectedValueOnce(new Error("offline"));
  render(<App />);
  await screen.findByText("Explorer unavailable");
  await act(async () => { poll(); });
  await userEvent.setup().click(screen.getByRole("button", { name: "Retry" }));
  expect(await screen.findByText("Explorer unavailable")).toBeInTheDocument();
  await act(async () => { resolveEarlier?.({ data: demoSnapshot, preview: false }); });
  expect(screen.getByText("Explorer unavailable")).toBeInTheDocument();
  expect(screen.queryByRole("heading", { name: "Latest blocks" })).not.toBeInTheDocument();
});

test("automatic polling does not starve a slow successful response", async () => {
  const poll = capturePoll();
  let complete: ((value: ExplorerLoad) => void) | undefined;
  vi.mocked(loadExplorer).mockReturnValueOnce(new Promise<ExplorerLoad>((resolve) => { complete = resolve; }));
  render(<App />);
  await act(async () => { poll(); poll(); });
  expect(loadExplorer).toHaveBeenCalledTimes(1);
  await act(async () => { complete?.({ data: demoSnapshot, preview: false }); });
  expect(await screen.findByRole("heading", { name: "Latest blocks" })).toBeInTheDocument();
});

test("navigation closes after choosing a section", async () => {
  render(<App />);
  await screen.findByRole("heading", { name: "Latest blocks" });
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Toggle navigation" }));
  expect(screen.getByRole("navigation", { name: "Explorer navigation" })).toHaveClass("is-open");
  await user.click(screen.getByRole("link", { name: "Network" }));
  expect(screen.getByRole("navigation", { name: "Explorer navigation" })).not.toHaveClass("is-open");
});
