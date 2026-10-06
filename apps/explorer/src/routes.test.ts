import { expect, test } from "vitest";
import { parseRoute, viewPath } from "./routes";
import { addressFixture, fixtureAddress } from "./test/addressFixture";

test("parses the pages the explorer serves from a path", () => {
  expect(parseRoute("/")).toEqual({ kind: "overview" });
  expect(parseRoute("")).toEqual({ kind: "overview" });
  expect(parseRoute(`/address/${fixtureAddress.toUpperCase()}`)).toEqual({ kind: "address", address: fixtureAddress });
  expect(parseRoute(`/address/${fixtureAddress}/`)).toEqual({ kind: "address", address: fixtureAddress });
  expect(parseRoute("/block/42")).toEqual({ kind: "block", query: "42" });
  expect(parseRoute(`/block/${fixtureAddress}`)).toEqual({ kind: "block", query: fixtureAddress });
  expect(parseRoute(`/tx/${fixtureAddress}`)).toEqual({ kind: "transaction", txid: fixtureAddress });
  expect(parseRoute(`/transaction/${fixtureAddress}`)).toEqual({ kind: "transaction", txid: fixtureAddress });
});

test("rejects paths that name nothing", () => {
  for (const path of ["/address", "/address/abc", `/address/${fixtureAddress}/extra`, "/wallet/" + fixtureAddress,
    "/block/18446744073709551616", "/block/-1", "/block/1e3", "/tx/42", "/address/%E0%A4%A", "/nope"]) {
    expect(parseRoute(path), path).toBeNull();
  }
});

test("view paths round-trip through the parser", () => {
  const address = addressFixture({ address: fixtureAddress.toUpperCase() });
  expect(viewPath({ kind: "overview" })).toBe("/");
  expect(parseRoute(viewPath({ kind: "address", address }))).toEqual({ kind: "address", address: fixtureAddress });
});
