"""Menu-owned native workspace. Imports AppKit only when opened on macOS."""
from __future__ import annotations
from pathlib import Path
import shlex
import json
import threading
from workspace_files import selected_files, validate_files, safe_name, make_archive

_CONTROLLER = None


def prepare(paths: list[str], command_text: str, output_text: str) -> tuple:
    files = {}
    for value in paths:
        path = Path(value)
        if path.name in files:
            raise ValueError('Selected files must have distinct names')
        files.update(selected_files(path.parent, [path.name]))
    files = validate_files(files)
    command = shlex.split(command_text)
    if not command or not command[0].startswith('/'):
        raise ValueError('Use an absolute in-image executable')
    outputs = [safe_name(v.strip()) for v in output_text.split(',') if v.strip()]
    if not outputs or len(outputs) > 20 or len(set(outputs)) != len(outputs):
        raise ValueError('Choose 1 to 20 distinct output filenames')
    return files, command, outputs


def is_busy() -> bool:
    return bool(_CONTROLLER is not None and _CONTROLLER.busy)


def open_workspace() -> None:
    global _CONTROLLER
    if _CONTROLLER is None:
        _CONTROLLER = _build()
    from AppKit import NSApp
    NSApp.activateIgnoringOtherApps_(True)
    _CONTROLLER.panel.makeKeyAndOrderFront_(None)


def _build():
    import objc
    from AppKit import (NSPanel, NSMakeRect, NSBackingStoreBuffered,
                        NSWindowStyleMaskTitled, NSWindowStyleMaskClosable,
                        NSFloatingWindowLevel, NSTextField, NSTextView, NSScrollView,
                        NSButton, NSOpenPanel, NSSavePanel, NSAlert, NSModalResponseOK,
                        NSAlertFirstButtonReturn, NSPopUpButton, NSImageView, NSImage, NSSound)
    from Foundation import NSObject

    class WorkspaceController(NSObject):
        def init(self):
            self = objc.super(WorkspaceController, self).init()
            if self is None:
                return None
            self.paths = []
            self.busy = False
            self.download = None
            self.panel = NSPanel.alloc().initWithContentRect_styleMask_backing_defer_(
                NSMakeRect(0, 0, 590, 660), NSWindowStyleMaskTitled | NSWindowStyleMaskClosable,
                NSBackingStoreBuffered, False)
            self.panel.setTitle_('SwarmGuard - Agent safety')
            self.panel.setReleasedWhenClosed_(False)
            self.panel.setLevel_(NSFloatingWindowLevel)
            self.panel.center()
            self.workspace_views = []
            self.top_views = []
            self.mode = 'Status'
            self.last_analysis = None
            self.visual_panel = None
            content = self.panel.contentView()
            def label(text, y, height=36):
                field = NSTextField.labelWithString_(text)
                field.setFrame_(NSMakeRect(18, y, 554, height))
                field.setLineBreakMode_(0)
                content.addSubview_(field)
                return field
            def button(text, selector, x, y, width):
                view = NSButton.alloc().initWithFrame_(NSMakeRect(x, y, width, 30))
                view.setTitle_(text);view.setBezelStyle_(1)
                view.setTarget_(self);view.setAction_(selector);content.addSubview_(view)
                return view
            def entry(text, y):
                field = NSTextField.alloc().initWithFrame_(NSMakeRect(18, y, 554, 28))
                field.setStringValue_(text);content.addSubview_(field);return field
            self.sections = NSPopUpButton.alloc().initWithFrame_pullsDown_(NSMakeRect(18, 616, 330, 28), False)
            self.sections.addItemsWithTitles_(['Status', 'Attack catalog', 'Policy checks', 'Activity and evidence', 'Latest analysis', 'Workspace', 'About'])
            self.sections.setTarget_(self);self.sections.setAction_('sectionChanged:');content.addSubview_(self.sections)
            button('Show details', 'sectionChanged:', 365, 616, 205)
            self.scenarios = NSPopUpButton.alloc().initWithFrame_pullsDown_(NSMakeRect(18, 578, 330, 28), False)
            self.scenarios.addItemsWithTitles_(['Hidden document trap', 'Stolen keys over network', 'Webpage hijack'])
            content.addSubview_(self.scenarios)
            button('Review AI demo...', 'demoClicked:', 365, 578, 205)
            button('Sound preview', 'soundClicked:', 18, 540, 170)
            button('Clear latest notice', 'clearClicked:', 200, 540, 175)
            button('Refresh status', 'sectionChanged:', 385, 540, 185)
            button('View latest visual evidence', 'visualClicked:', 18, 502, 265)
            self.top_views = list(content.subviews())[2:]
            before_workspace = len(content.subviews())
            label('Offline copied files only. No host mounts, keys, downloads or cloud agents.\nAgents running elsewhere are not protected.', 598, 44)
            self.check_button = button('Run complete offline check', 'checkClicked:', 18, 556, 265)
            self.pick_button = button('Choose source files...', 'chooseClicked:', 300, 556, 270)
            self.selection = label('No files selected. Only explicitly chosen source is read.', 514)
            label('Trusted in-image command (absolute executable):', 480, 22)
            self.command = entry("/bin/sh -c 'cat input.txt > result.txt'", 449)
            label('Requested output filenames (comma separated, up to 20):', 417, 22)
            self.exports = entry('result.txt', 387)
            label('1 MiB/file, 4 MiB total. Hidden/credential-like paths refused.\nSecret detection is not exhaustive. Never choose private documents or keys.', 333, 43)
            self.run_button = button('Review and run copies', 'runClicked:', 18, 291, 265)
            self.save_button = button('Save outputs for review...', 'saveClicked:', 300, 291, 270)
            self.save_button.setEnabled_(False)
            self.workspace_views = list(content.subviews())[before_workspace:]
            for view in self.workspace_views:
                frame = view.frame()
                view.setFrameOrigin_((frame.origin.x, frame.origin.y - 32))
            scroll = NSScrollView.alloc().initWithFrame_(NSMakeRect(18, 48, 554, 229))
            self.scroll = scroll
            scroll.setHasVerticalScroller_(True)
            self.results = NSTextView.alloc().initWithFrame_(NSMakeRect(0, 0, 534, 229))
            self.results.setEditable_(False)
            self.results.setString_('Not checked. This is experimental isolation, not whole-Mac protection.\nThe complete check uses synthetic source only.')
            self.results.setVerticallyResizable_(True)
            self.results.setHorizontallyResizable_(False)
            self.results.textContainer().setWidthTracksTextView_(True)
            scroll.setDocumentView_(self.results);content.addSubview_(scroll)
            label('Outputs never overwrite originals automatically. Review before using them.', 12, 24)
            self.panel.setDelegate_(self)
            self.sectionChanged_(None)
            return self

        def sectionChanged_(self, _sender):
            if self.busy:
                return
            self.mode = str(self.sections.titleOfSelectedItem())
            workspace = self.mode == 'Workspace'
            for view in self.workspace_views:
                view.setHidden_(not workspace)
            for view in self.top_views:
                view.setHidden_(workspace)
            self.scroll.setFrame_(NSMakeRect(18, 48, 554, 197 if workspace else 430))
            if workspace:
                self.results.setString_('Offline scratch only. Run the complete check first. No cloud agent is installed.');return
            try:
                from native_overview import section_text
                self.results.setString_(section_text(self.mode))
            except Exception as exc:
                self.showError_('Details unavailable (' + type(exc).__name__ + '). No model call was made.')

        def visualClicked_(self, _sender):
            # Only fixed, repository-owned synthetic artifacts, never paths from external content.
            root = Path(__file__).resolve().parent
            candidates = [root / 'assets' / 'poisoned_webpage.png', root / 'assets' / 'poisoned_readme.png']
            artifact = next((p for p in candidates if p.is_file() and not p.is_symlink()), None)
            if artifact is None:
                self.showError_('No local synthetic visual artifact exists yet. No private file opened.');return
            image = NSImage.alloc().initWithContentsOfFile_(str(artifact))
            if image is None:
                self.showError_('Visual artifact could not be loaded.');return
            self.visual_panel = NSPanel.alloc().initWithContentRect_styleMask_backing_defer_(
                NSMakeRect(0, 0, 590, 400), NSWindowStyleMaskTitled | NSWindowStyleMaskClosable,
                NSBackingStoreBuffered, False)
            self.visual_panel.setReleasedWhenClosed_(False)
            self.visual_panel.setTitle_('Synthetic visual artifact - not a real host attack')
            view = NSImageView.alloc().initWithFrame_(NSMakeRect(10, 10, 570, 380))
            view.setImage_(image);view.setImageScaling_(0)
            self.visual_panel.contentView().addSubview_(view)
            self.visual_panel.center();self.visual_panel.makeKeyAndOrderFront_(None)

        def soundClicked_(self, _sender):
            NSSound.soundNamed_('Glass').play()

        def clearClicked_(self, _sender):
            if self.busy:
                return
            from threat_bus import reset_to_safe
            reset_to_safe('Notice cleared by user. Scoped tool policy unchanged.', last_action='user_ack')
            self.sectionChanged_(None)

        def demoClicked_(self, _sender):
            if self.busy:
                return
            try:
                from swarm_brain import api_status
                if not api_status().get('configured'):
                    self.showError_('AI key missing or analysis unavailable. No demo ran. Free policy and offline checks still work.');return
            except ImportError:
                self.showError_('Analysis dependencies unavailable in this Python. No installation or model request attempted.');return
            review = NSAlert.alloc().init()
            review.setMessageText_('Run this synthetic AI demo using API credits?')
            review.setInformativeText_('This can call the configured Meta models and use credits. The final cost is not known here. Cancel unless you approve that use. It is a pretend attack: no real host process is quarantined. No personal project files are supplied by this demo.')
            review.addButtonWithTitle_('Run using API credits');review.addButtonWithTitle_('Cancel')
            if review.runModal() != NSAlertFirstButtonReturn:
                return
            scenario = ['steal_env', 'mcp_exfil', 'webpage_hijack'][self.scenarios.indexOfSelectedItem()]
            def operation():
                from autonomy import run_autonomous_scenario
                result, incident = run_autonomous_scenario(scenario, trigger='native_user_approved_demo')
                self.last_analysis = result
                return json.dumps({'result': result, 'incident': incident}, indent=2, ensure_ascii=False), None
            self.startWorker_(operation)

        def setBusy_(self, value):
            self.busy = bool(value)
            for view in (self.check_button, self.pick_button, self.run_button, self.command, self.exports):
                view.setEnabled_(not self.busy)
            self.save_button.setEnabled_(not self.busy and self.download is not None)

        def showError_(self, text):
            self.results.setString_(str(text))

        def chooseClicked_(self, _sender):
            if self.busy:
                return
            chooser = NSOpenPanel.openPanel()
            chooser.setCanChooseDirectories_(False);chooser.setCanChooseFiles_(True)
            chooser.setAllowsMultipleSelection_(True)
            chooser.setMessage_('Choose only source files you want copied. No keys or private documents.')
            if chooser.runModal() == NSModalResponseOK:
                paths = [str(url.path()) for url in chooser.URLs()]
                try:
                    files, _, _ = prepare(paths, str(self.command.stringValue()), str(self.exports.stringValue()))
                    self.paths = paths
                    self.selection.setStringValue_(f'{len(files)} source files selected. Review shows every name before launch.')
                    self.results.setString_('Selected files:\n' + '\n'.join(files))
                    self.download = None;self.save_button.setEnabled_(False)
                except Exception as exc:
                    self.paths = [];self.selection.setStringValue_('Selection refused. Choose safe source files.')
                    self.showError_(str(exc))

        def startWorker_(self, operation):
            self.setBusy_(True)
            self.download = None
            self.results.setString_('Running offline. No private host folders or network access. Waiting for cleanup...')
            def worker():
                try:
                    message, download = operation()
                    self.download = download
                except Exception as exc:
                    message = str(exc) if isinstance(exc, (ValueError, RuntimeError)) else type(exc).__name__ + ': operation failed. Do not bypass restrictions.'
                    self.download = None
                self.performSelectorOnMainThread_withObject_waitUntilDone_('finished:', message, False)
            threading.Thread(target=worker, daemon=True).start()

        def finished_(self, message):
            self.results.setString_(str(message))
            self.setBusy_(False)

        def checkClicked_(self, _sender):
            if self.busy:
                return
            def operation():
                from isolation_check import check, check_workspace
                result = check()
                lines = ['PASS: ' + name if passed else 'FAIL: ' + name for name, passed in result['checks'].items()]
                if result['passed']:
                    copied = check_workspace()
                    lines.append(('PASS: ' if copied['passed'] else 'FAIL: ') + copied['detail'])
                    result['passed'] = copied['passed']
                elif result.get('detail'):
                    lines.append(result['detail'])
                lines.insert(0, 'Offline check passed.' if result['passed'] else 'Offline check failed or unavailable.')
                lines.extend(['Checked: ' + result['checked_at'], 'Not whole-Mac protection. No installed cloud agent.'])
                return '\n'.join(lines), None
            self.startWorker_(operation)

        def runClicked_(self, _sender):
            if self.busy:
                return
            try:
                # Read once, review those exact bytes/names, then run that snapshot.
                files, command, outputs = prepare(self.paths, str(self.command.stringValue()), str(self.exports.stringValue()))
                review = NSAlert.alloc().init()
                review.setMessageText_('Run these exact source copies offline?')
                review.setInformativeText_('Imports:\n' + '\n'.join(files) + '\n\nCommand: ' + shlex.join(command) + '\n\nOutputs:\n' + '\n'.join(outputs) + '\n\nNo host mounts or network. Originals stay unchanged. Exported content is untrusted until reviewed.')
                review.addButtonWithTitle_('Run copies');review.addButtonWithTitle_('Cancel')
                if review.runModal() != NSAlertFirstButtonReturn:
                    return
            except Exception as exc:
                self.showError_(str(exc));return
            def operation():
                from offline_workspace import run
                from isolation_check import VERIFIED_IMAGE
                result = run(files, command, outputs, image=VERIFIED_IMAGE)
                return ('Run finished; scratch container removed. Save outputs for review.\n\n' + result['stdout'][-8000:]), make_archive(result['files'])
            self.startWorker_(operation)

        def saveClicked_(self, _sender):
            if self.busy or self.download is None:
                return
            chooser = NSSavePanel.savePanel()
            chooser.setNameFieldStringValue_('swarmguard-outputs-for-review.tar')
            chooser.setMessage_('Save selected outputs as a new archive. Review before applying to your project.')
            if chooser.runModal() == NSModalResponseOK:
                path = Path(str(chooser.URL().path()))
                try:
                    # Never overwrite an existing file even if a stale dialog selected it.
                    with path.open('xb') as stream:
                        stream.write(self.download)
                    self.results.setString_('Saved output archive: ' + str(path) + '\nOriginal project unchanged. Review archive contents before using them.')
                except Exception as exc:
                    self.showError_('Save refused (' + type(exc).__name__ + '). Choose a new filename. No existing file overwritten.')

        def windowShouldClose_(self, _sender):
            self.panel.orderOut_(None)
            return False

    return WorkspaceController.alloc().init()
