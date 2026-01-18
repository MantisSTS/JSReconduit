import * as vscode from "vscode";
import { ProjectWatcher } from "./indexer";
import { JSReconduitStore } from "./store";
import { JSReconduitTreeProvider } from "./tree";
import { exportFindings } from "./exporter";
import { writeInstrumentationSnippet } from "./instrumentation";
import { writeReport } from "./report";
import { expandHome, logError } from "./utils";
import { writeWordlist } from "./wordlist";

function getBaseDir(): string {
  const config = vscode.workspace.getConfiguration("jsreconduit");
  const baseDir = config.get<string>("baseDir", "~/burp-js-capture");
  return expandHome(baseDir);
}

function getWordlistOverride(): string {
  const config = vscode.workspace.getConfiguration("jsreconduit");
  return config.get<string>("wordlistPath", "");
}

function getAutoWordlist(): boolean {
  const config = vscode.workspace.getConfiguration("jsreconduit");
  return config.get<boolean>("autoWordlist", true);
}

function getAutoDeobfuscate(): boolean {
  const config = vscode.workspace.getConfiguration("jsreconduit");
  return config.get<boolean>("autoDeobfuscate", false);
}

function getPreferDeobfuscated(): boolean {
  const config = vscode.workspace.getConfiguration("jsreconduit");
  return config.get<boolean>("preferDeobfuscated", true);
}

function getExportDir(): string {
  const config = vscode.workspace.getConfiguration("jsreconduit");
  return config.get<string>("exportDir", "");
}

function getReportDir(): string {
  const config = vscode.workspace.getConfiguration("jsreconduit");
  return config.get<string>("reportDir", "");
}

function getSignaturePath(): string {
  const config = vscode.workspace.getConfiguration("jsreconduit");
  return config.get<string>("signaturePath", "");
}

function getAutoWriteSnippet(): boolean {
  const config = vscode.workspace.getConfiguration("jsreconduit");
  return config.get<boolean>("autoWriteSnippet", true);
}

export function activate(context: vscode.ExtensionContext): void {
  const output = vscode.window.createOutputChannel("JSReconduit");
  const store = new JSReconduitStore(output);
  const provider = new JSReconduitTreeProvider(store.snapshot());

  const refresh = async () => {
    const baseDir = getBaseDir();
    await store.refresh(baseDir, {
      autoDeobfuscate: getAutoDeobfuscate(),
      preferDeobfuscated: getPreferDeobfuscated(),
      signaturePath: getSignaturePath(),
    });
    provider.update(store.snapshot());
    if (getAutoWordlist()) {
      const snapshot = store.snapshot();
      const overridePath = getWordlistOverride();
      try {
        await writeWordlist(baseDir, new Set(snapshot.wordlist), overridePath);
      } catch (error) {
        logError(output, "Failed to auto-write wordlist", error);
      }
    }
    if (getAutoWriteSnippet()) {
      try {
        await writeInstrumentationSnippet(baseDir);
      } catch (error) {
        logError(output, "Failed to write instrumentation snippet", error);
      }
    }
  };

  const watcher = new ProjectWatcher(getBaseDir(), refresh, output);
  watcher.start().then(refresh);

  context.subscriptions.push(
    vscode.window.registerTreeDataProvider("jsreconduit.view", provider),
    watcher,
    output
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("jsreconduit.refresh", refresh),
    vscode.commands.registerCommand("jsreconduit.deobfuscateAll", async () => {
      const baseDir = getBaseDir();
      await store.refresh(baseDir, {
        autoDeobfuscate: true,
        forceDeobfuscate: true,
        preferDeobfuscated: true,
        signaturePath: getSignaturePath(),
      });
      provider.update(store.snapshot());
      vscode.window.showInformationMessage("JSReconduit: deobfuscated outputs refreshed.");
    }),
    vscode.commands.registerCommand("jsreconduit.openLocation", async (filePath: string, line = 1, column = 1) => {
      try {
        const doc = await vscode.workspace.openTextDocument(filePath);
        const editor = await vscode.window.showTextDocument(doc, { preview: true });
        const pos = new vscode.Position(Math.max(line - 1, 0), Math.max(column - 1, 0));
        editor.selection = new vscode.Selection(pos, pos);
        editor.revealRange(new vscode.Range(pos, pos));
      } catch (error) {
        logError(output, "Failed to open location", error);
      }
    }),
    vscode.commands.registerCommand("jsreconduit.exportWordlist", async () => {
      const baseDir = getBaseDir();
      const snapshot = store.snapshot();
      const overridePath = getWordlistOverride();
      const path = await writeWordlist(baseDir, new Set(snapshot.wordlist), overridePath);
      vscode.window.showInformationMessage(`JSReconduit wordlist exported to ${path}`);
    }),
    vscode.commands.registerCommand("jsreconduit.exportFindingsJson", async () => {
      const baseDir = getBaseDir();
      const snapshot = store.snapshot();
      const exportPath = await exportFindings(baseDir, snapshot, "json", getExportDir());
      vscode.window.showInformationMessage(`JSReconduit findings exported to ${exportPath}`);
    }),
    vscode.commands.registerCommand("jsreconduit.exportFindingsCsv", async () => {
      const baseDir = getBaseDir();
      const snapshot = store.snapshot();
      const exportPath = await exportFindings(baseDir, snapshot, "csv", getExportDir());
      vscode.window.showInformationMessage(`JSReconduit findings exported to ${exportPath}`);
    }),
    vscode.commands.registerCommand("jsreconduit.exportFindingsSarif", async () => {
      const baseDir = getBaseDir();
      const snapshot = store.snapshot();
      const exportPath = await exportFindings(baseDir, snapshot, "sarif", getExportDir());
      vscode.window.showInformationMessage(`JSReconduit SARIF exported to ${exportPath}`);
    }),
    vscode.commands.registerCommand("jsreconduit.generateReport", async () => {
      const baseDir = getBaseDir();
      const snapshot = store.snapshot();
      const reportPath = await writeReport(baseDir, snapshot, getReportDir());
      vscode.window.showInformationMessage(`JSReconduit report written to ${reportPath}`);
    }),
    vscode.commands.registerCommand("jsreconduit.writeSnippet", async () => {
      const baseDir = getBaseDir();
      const snippetPath = await writeInstrumentationSnippet(baseDir);
      vscode.window.showInformationMessage(`JSReconduit snippet written to ${snippetPath}`);
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("jsreconduit.baseDir")) {
        watcher.updateBaseDir(getBaseDir());
      }
      if (
        event.affectsConfiguration("jsreconduit.wordlistPath") ||
        event.affectsConfiguration("jsreconduit.autoWordlist") ||
        event.affectsConfiguration("jsreconduit.autoDeobfuscate") ||
        event.affectsConfiguration("jsreconduit.preferDeobfuscated") ||
        event.affectsConfiguration("jsreconduit.exportDir") ||
        event.affectsConfiguration("jsreconduit.reportDir") ||
        event.affectsConfiguration("jsreconduit.signaturePath") ||
        event.affectsConfiguration("jsreconduit.autoWriteSnippet")
      ) {
        refresh();
      }
    })
  );
}

export function deactivate(): void {}
