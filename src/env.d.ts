/// <reference path="../.astro/types.d.ts" />

declare namespace App {
  interface Locals {
    cfContext?: ExecutionContext;
    lang?: 'zh' | 'en';
  }
}
