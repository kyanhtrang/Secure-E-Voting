import { defineConfig, devices } from '@playwright/test';
export default defineConfig({testDir:'./tests/voting-browser',workers:1,retries:0,reporter:'list',
  use:{baseURL:'http://127.0.0.1:5178',...devices['Desktop Chrome'],...(process.platform==='win32' ? {channel:'msedge'} : {}),trace:'off',video:'off',screenshot:'off'},
  webServer:{command:'node tests/voting_fixture.mjs --synthetic-voting-only',url:'http://127.0.0.1:5178',reuseExistingServer:false,timeout:60000,stdout:'ignore',stderr:'pipe'},
});
