import * as vscode from 'vscode';

import { TomboCrypt } from './tombo_crypto';

const ENCODE="shift-jis";

export function activate(context: vscode.ExtensionContext) {
	// Register our custom editor providers
	context.subscriptions.push(
		vscode.workspace.onDidOpenTextDocument(async (document) => {
			// 拡張子が '.chi' のファイルか確認
			if (document.fileName.endsWith('.chi')) {
				// パスコードを尋ねる
				const passcode = await vscode.window.showInputBox({
					prompt: 'Please enter the passcode for this .chi file.',
					password: true,
					ignoreFocusOut: true,
				});

				if (!passcode) {
					vscode.window.showInformationMessage('Decryption canceled.');
					return;
				}

				try {
					// ファイルをバイナリとして読み込む
					const fileUri = vscode.Uri.file(document.fileName);
					const fileData = await vscode.workspace.fs.readFile(fileUri);

					// 復号処理
					const crypt = new TomboCrypt();
					const passcodeUint8 = TomboCrypt.passcode(new TextEncoder().encode(passcode));
					const decryptedData = crypt.decode(passcodeUint8, fileData);

					if (!decryptedData) {
						vscode.window.showErrorMessage('Failed to decrypt the file. Please check the passcode.');
						return;
					}

					// 復号されたデータを文字列に変換
					const decryptedText = new TextDecoder(ENCODE).decode(decryptedData);

					// 新しいテキストドキュメントとして表示
					const newDocument : vscode.TextDocument = await vscode.workspace.openTextDocument({ content: decryptedText });
					await vscode.window.showTextDocument(newDocument);

				} catch (error) {
					vscode.window.showErrorMessage(`An error occurred: ${error}`);
				}
			}
		})
	);

}
