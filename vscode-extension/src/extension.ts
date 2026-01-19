import * as vscode from "vscode";
import { ProjectWatcher } from "./indexer";
import { JSReconduitStore } from "./store";
import { JSReconduitTreeProvider } from "./tree";
import { exportFindings } from "./exporter";
import { writeInstrumentationSnippet } from "./instrumentation";
import { writeReport } from "./report";
import { DriftEntry } from "./types";
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
  const diffDecoration = vscode.window.createTextEditorDecorationType({
    backgroundColor: new vscode.ThemeColor("editor.rangeHighlightBackground"),
    overviewRulerColor: new vscode.ThemeColor("editorOverviewRuler.infoForeground"),
    overviewRulerLane: vscode.OverviewRulerLane.Right,
  });

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
    vscode.commands.registerCommand("jsreconduit.openDiff", async (drift: DriftEntry) => {
      try {
        if (!drift.fromPath || !drift.toPath) {
          vscode.window.showWarningMessage("JSReconduit: diff paths unavailable for this asset.");
          return;
        }
        const left = vscode.Uri.file(drift.fromPath);
        const right = vscode.Uri.file(drift.toPath);
        await vscode.commands.executeCommand(
          "vscode.diff",
          left,
          right,
          `JSReconduit Diff: ${drift.url}`
        );
        const ranges: vscode.Range[] = [];
        const added = drift.added;
        const highlightFindings = [...added.endpoints, ...added.sinks, ...added.userSinks];
        for (const finding of highlightFindings.slice(0, 200)) {
          if (!finding.location) {
            continue;
          }
          const line = Math.max(finding.location.line - 1, 0);
          const col = Math.max((finding.location.column || 1) - 1, 0);
          ranges.push(new vscode.Range(line, col, line, col + 1));
        }
        setTimeout(() => {
          const editors = vscode.window.visibleTextEditors.filter(
            (editor) => editor.document.uri.fsPath === drift.toPath
          );
          for (const editor of editors) {
            editor.setDecorations(diffDecoration, ranges);
          }
        }, 200);
      } catch (error) {
        logError(output, "Failed to open diff", error);
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
    }),
    vscode.commands.registerCommand("jsreconduit.goToRoute", async () => {
      const routes = store.snapshot().routes;
      if (routes.length === 0) {
        vscode.window.showInformationMessage("JSReconduit: no routes captured yet.");
        return;
      }
      const pickedRoute = await vscode.window.showQuickPick(
        routes.map((route) => ({
          label: route.route,
          description: `${route.assets.length} assets`,
          route,
        })),
        { placeHolder: "Select a route" }
      );
      if (!pickedRoute) {
        return;
      }
      const assets = pickedRoute.route.assets;
      if (assets.length === 0) {
        vscode.window.showInformationMessage("JSReconduit: no assets for that route.");
        return;
      }
      const pickedAsset = await vscode.window.showQuickPick(
        assets.map((asset) => ({
          label: asset.asset.original_filename || asset.asset.url,
          description: asset.analysisPath,
          asset,
        })),
        { placeHolder: "Select an asset" }
      );
      if (!pickedAsset) {
        return;
      }
      await vscode.commands.executeCommand("jsreconduit.openLocation", pickedAsset.asset.analysisPath, 1, 1);
    }),
    vscode.commands.registerCommand("jsreconduit.goToAsset", async () => {
      const assets = store.snapshot().assets;
      if (assets.length === 0) {
        vscode.window.showInformationMessage("JSReconduit: no assets captured yet.");
        return;
      }
      const pickedAsset = await vscode.window.showQuickPick(
        assets.map((asset) => ({
          label: asset.asset.original_filename || asset.asset.url,
          description: asset.analysisPath,
          asset,
        })),
        { placeHolder: "Select an asset" }
      );
      if (!pickedAsset) {
        return;
      }
      await vscode.commands.executeCommand("jsreconduit.openLocation", pickedAsset.asset.analysisPath, 1, 1);
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

  context.subscriptions.push(diffDecoration);
}

export function deactivate(): void {}
