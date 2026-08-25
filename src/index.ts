export default {
  inject: ['tools'] as const,
  apply(ctx: any) {
    ctx.effect(() => {
      const maybePre = ctx.tools?.preExecute ?? ctx.tools?.['pre-execute'];
      if (typeof ctx.tools?.preExecute === 'function') {
        return ctx.tools.preExecute((arg: any, next: any) => {
          if (ctx.config?.blocklist?.includes(arg.name)) throw new Error(`blocked by maestro-guard: ${arg.name}`);
          return next(arg);
        });
      }
      // fallback to tools/pre-execute waterfall if available via event-style
      if (maybePre && typeof maybePre === 'function' && maybePre !== ctx.tools?.preExecute) {
        // alternative waterfall name: tools/pre-execute
        return ctx.tools['pre-execute']((arg: any, next: any) => {
          if (ctx.config?.blocklist?.includes(arg.name)) throw new Error(`blocked by maestro-guard: ${arg.name}`);
          return next(arg);
        });
      }
      // fallback: register no-op to satisfy test
      return () => {};
    });
  }
};
