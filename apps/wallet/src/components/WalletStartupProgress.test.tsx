import {act, cleanup, fireEvent, render, screen} from '@testing-library/react';
import {afterEach, beforeEach, expect, it, vi} from 'vitest';
import {getWalletStartupStatus} from '../api/nodeClient';
import type {WalletStartupStatus} from '../types';
import {WalletStartupProgress} from './WalletStartupProgress';
vi.mock('../api/nodeClient', () => ({getWalletStartupStatus: vi.fn()}));
const progress: WalletStartupStatus = {phase:'checking_proofs', completed:700, total:1000, elapsed_seconds:184, seconds_since_progress:1, active:true, error:null, available_disk_bytes:20 * 2 ** 30};
beforeEach(() => {vi.useFakeTimers(); vi.mocked(getWalletStartupStatus).mockReset();});
afterEach(() => {cleanup(); vi.useRealTimers();});
it('updates measured proof counts and stops polling after unmount', async () => {
  vi.mocked(getWalletStartupStatus).mockResolvedValueOnce(progress).mockResolvedValue({...progress,completed:701});
  let view: ReturnType<typeof render>;
  await act(async () => {view=render(<WalletStartupProgress/>);});
  expect(screen.getByText('700 of 1,000 stored blocks checked')).toBeInTheDocument();
  expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow','70');
  await act(async () => {await vi.advanceTimersByTimeAsync(1000);});
  expect(screen.getByText('701 of 1,000 stored blocks checked')).toBeInTheDocument();
  view!.unmount();
  await act(async () => {await vi.advanceTimersByTimeAsync(3000);});
  expect(getWalletStartupStatus).toHaveBeenCalledTimes(2);
});
it('does not invent a percentage for an unmeasured phase', async () => {
  vi.mocked(getWalletStartupStatus).mockResolvedValue({...progress,phase:'checking_inputs',completed:0,total:null});
  await act(async () => {render(<WalletStartupProgress/>);});
  expect(screen.getByRole('progressbar')).not.toHaveAttribute('aria-valuenow');
  expect(screen.getByText('Elapsed: 3m 4s')).toBeInTheDocument();
  expect(screen.queryByText(/% of this step/)).not.toBeInTheDocument();
});
it('keeps the last count and explains an unavailable status connection', async () => {
  vi.mocked(getWalletStartupStatus).mockResolvedValueOnce(progress).mockRejectedValue(Error('offline'));
  await act(async () => {render(<WalletStartupProgress/>);});
  await act(async () => {await vi.advanceTimersByTimeAsync(1000);});
  expect(screen.getByText('700 of 1,000 stored blocks checked')).toBeInTheDocument();
  expect(screen.getByText(/Live startup details are temporarily unavailable/)).toBeInTheDocument();
});
it('shows low disk space and a terminal error without a moving bar', async () => {
  vi.mocked(getWalletStartupStatus).mockResolvedValue({...progress,phase:'failed',active:false,available_disk_bytes:0.84*2**30,error:{code:'disk_full',message:'There is not enough space on the disk.',retryable:true}});
  await act(async () => {render(<WalletStartupProgress/>);});
  expect(screen.getByText(/Low disk space: 0.84 GiB/)).toBeInTheDocument();
  expect(screen.getByText('There is not enough space on the disk.')).toBeInTheDocument();
  expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
});
it('copies startup counters for support', async () => {
  vi.mocked(getWalletStartupStatus).mockResolvedValue(progress);
  const writeText=vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText}});
  await act(async () => {render(<WalletStartupProgress/>);});
  await act(async () => {fireEvent.click(screen.getByRole('button',{name:'Copy startup details'}));});
  expect(JSON.parse(writeText.mock.calls[0][0]).wallet_startup.completed).toBe(700);
  expect(screen.getByText('Startup details copied')).toBeInTheDocument();
});
