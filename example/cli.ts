export async function run(args: string[]): Promise<void> {
  const [command, ..._rest] = args;

  if (!command || command === "help" || command === "--help" || command === "-h") {
    // printHelp();
    return;
  }

  if (command === "version" || command === "--version" || command === "-v") {
    console.log("OhMyMsg CLI v1.0.0");
    return;
  }

  switch (command) {
    // case "scan": {
    //   const { scanCommand } = await import("./commands/scan");
    //   await scanCommand(rest);
    //   return;
    // }
    default: {
      console.error(`Unknown command: ${command}`);
      // printHelp();
    }
  }
}
