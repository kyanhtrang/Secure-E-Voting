import { defineConfig,devices } from '@playwright/test';
export default defineConfig({testDir:'./tests/board-browser',workers:1,retries:0,reporter:'list',
  use:{baseURL:'http://127.0.0.1:5191',...devices['Desktop Chrome'],...(process.platform==='win32'?{channel:'msedge'}:{}),
    screenshot:'off',trace:'off',video:'off'},
  webServer:{command:`"${process.env.EVOTE_TEST_PYTHON??'python'}" tests/board_fixture.py --synthetic-board-only`,
    url:'http://127.0.0.1:5191',reuseExistingServer:false,timeout:60000,stdout:'ignore',stderr:'pipe'},
});
