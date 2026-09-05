import { defineConfig } from '@playwright/test';
export default defineConfig({testDir:'e2e',workers:1,use:{baseURL:'http://127.0.0.1:8000',channel:'chrome',viewport:{width:1440,height:1000}},reporter:'list'});
