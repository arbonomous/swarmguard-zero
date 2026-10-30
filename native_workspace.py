"""Menu-owned native workspace. Imports AppKit only when opened on macOS."""
from __future__ import annotations
from pathlib import Path
import shlex
import json
import threading
from workspace_files import selected_files, validate_files, safe_name, make_archive

_CONTROLLER = None


def require_offline_native_operation(kind):
    # All native inference routes stay closed, including legacy demo callbacks.
    # A future paid flow needs a separate approval design, not a boolean flip.
    if kind not in ('workspace', 'check'):
        raise PermissionError('Native paid AI tasks and demos are paused. Nothing started.')


def dry_manifest():
    # Fixed manifest shared by review and dry start; never enables provider work.
    from execution_gate import Manifest
    from native_model_task import SOURCE, TASK, REVIEW
    from meta_agent import MODEL, BASE_URL, TOOLS
    from managed_model import RELAY
    from isolation_check import VERIFIED_IMAGE
    return Manifest.build({'sales.txt': SOURCE}, TASK, endpoint=BASE_URL, model=MODEL,
                          tools=TOOLS, image=VERIFIED_IMAGE, command=RELAY, warning=REVIEW)


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


def check_summary(text: str) -> str:
    """Keep raw protocol evidence out of the normal result view."""
    return text.split('\n\nEvidence:', 1)[0]


def is_busy() -> bool:
    return bool(_CONTROLLER is not None and _CONTROLLER.busy)


def present_panel(panel, app, running_app, activation_options) -> None:
    """Visibility must not depend on the accessory activation request succeeding."""
    panel.setHidesOnDeactivate_(False)
    activated = running_app.activateWithOptions_(activation_options)
    panel.makeKeyWindow()
    panel.orderFrontRegardless()
    print('[SwarmGuard] Presentation visible=' + str(bool(panel.isVisible())) +
          ' key=' + str(bool(panel.isKeyWindow())) +
          ' active=' + str(bool(app.isActive())) +
          ' activation_accepted=' + str(bool(activated)), flush=True)


def open_workspace(section: str = "Workspace", status_item=None) -> None:
    global _CONTROLLER
    if _CONTROLLER is None:
        _CONTROLLER = _build()
    _CONTROLLER.sections.selectItemWithTitle_(section)
    _CONTROLLER.sectionChanged_(None)
    from AppKit import NSApplication, NSRunningApplication, NSApplicationActivateIgnoringOtherApps
    if status_item is not None:
        try:
            button = status_item.button()
            window = button.window()
            screen = window.screen()
            anchor = window.convertRectToScreen_(button.convertRect_toView_(button.bounds(), None))
            visible = screen.visibleFrame()
            size = _CONTROLLER.panel.frame().size
            x = max(visible.origin.x + 8, min(anchor.origin.x + anchor.size.width / 2 - size.width / 2,
                                             visible.origin.x + visible.size.width - size.width - 8))
            y = max(visible.origin.y + 8, anchor.origin.y - size.height - 28)
            _CONTROLLER.panel.setFrameOrigin_((x, y))
        except (AttributeError, TypeError):
            _CONTROLLER.panel.center()
    present_panel(_CONTROLLER.panel, NSApplication.sharedApplication(),
                  NSRunningApplication.currentApplication(), NSApplicationActivateIgnoringOtherApps)


def _build():
    import objc
    from AppKit import (NSPanel, NSMakeRect, NSBackingStoreBuffered,
                        NSWindowStyleMaskTitled, NSWindowStyleMaskClosable,
                        NSFloatingWindowLevel, NSTextField, NSTextView, NSScrollView,
                        NSButton, NSOpenPanel, NSSavePanel, NSAlert, NSModalResponseOK,
                        NSAlertFirstButtonReturn, NSPopUpButton, NSImageView, NSImage, NSSound,
                        NSPasteboard, NSPasteboardTypeString)
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
            from task_review import ReviewFlow
            self.review_flow = ReviewFlow()
            self.review_receipt = None
            self.execution_gate = None
            self.execution_ticket = None
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
            self.sections = NSPopUpButton.alloc().initWithFrame_pullsDown_(NSMakeRect(18, 540, 330, 28), False)
            self.sections.addItemsWithTitles_(['Status', 'Attack catalog', 'Policy checks', 'Activity and evidence', 'Latest analysis', 'Safety check', 'AI task', 'Workspace', 'About'])
            self.sections.setTarget_(self);self.sections.setAction_('sectionChanged:');content.addSubview_(self.sections)
            self.details_button = button('Show details', 'detailsClicked:', 365, 540, 205)
            mark = NSImage.alloc().initWithContentsOfFile_(str(Path(__file__).resolve().parent / 'assets' / 'brand' / 'swarmguard-mark.png'))
            brand = NSImageView.alloc().initWithFrame_(NSMakeRect(18, 596, 36, 36))
            self.brand_icon = mark
            brand.setImage_(mark);brand.setImageScaling_(0);content.addSubview_(brand)
            title = NSTextField.labelWithString_('SwarmGuard')
            title.setFrame_(NSMakeRect(66, 608, 280, 24));content.addSubview_(title)
            self.headline = label('Ready to check. This is not whole-Mac protection.', 572, 24)
            self.home_button = button('Test managed guard', 'guardClicked:', 365, 596, 205)
            before_details = len(content.subviews())
            self.scenarios = NSPopUpButton.alloc().initWithFrame_pullsDown_(NSMakeRect(18, 500, 330, 28), False)
            self.scenarios.addItemsWithTitles_(['Hidden document trap', 'Stolen keys over network', 'Webpage hijack'])
            content.addSubview_(self.scenarios)
            demo_button = button('AI demo paused', 'demoClicked:', 365, 500, 205)
            demo_button.setEnabled_(False)
            button('Sound preview', 'soundClicked:', 18, 462, 170)
            button('Clear latest notice', 'clearClicked:', 200, 462, 175)
            button('Refresh status', 'sectionChanged:', 385, 462, 185)
            button('View latest visual evidence', 'visualClicked:', 18, 424, 265)
            self.top_views = list(content.subviews())[before_details:]
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
                view.setFrameOrigin_((frame.origin.x, frame.origin.y - 110))
            scroll = NSScrollView.alloc().initWithFrame_(NSMakeRect(18, 48, 554, 229))
            self.scroll = scroll
            scroll.setHasVerticalScroller_(True)
            self.results = NSTextView.alloc().initWithFrame_(NSMakeRect(0, 0, 534, 229))
            self.results.setEditable_(False)
            self.results.setSelectable_(True)
            self.results.setString_('Not checked. This is experimental isolation, not whole-Mac protection.\nThe complete check uses synthetic source only.')
            self.results.setVerticallyResizable_(True)
            self.results.setHorizontallyResizable_(False)
            self.results.textContainer().setWidthTracksTextView_(True)
            scroll.setDocumentView_(self.results);content.addSubview_(scroll)
            self.footer = label('Outside agents on your Mac are not covered.', 12, 24)
            self.footer.setFrame_(NSMakeRect(18, 12, 380, 24))
            self.copy_button = button('Copy results', 'copyClicked:', 418, 10, 154)
            self.dry_button = button('Check start - no spend', 'dryStartClicked:', 18, 300, 554)
            self.dry_button.setEnabled_(False)
            self.base_frames = [(view, view.frame()) for view in content.subviews()]
            self.showing_check_details = False
            self.panel.setDelegate_(self)
            self.sectionChanged_(None)
            return self

        def sectionChanged_(self, _sender):
            if self.busy:
                return
            self.mode = str(self.sections.titleOfSelectedItem())
            compact = self.mode in ('Status', 'Safety check', 'AI task')
            self.panel.setContentSize_((590, 480 if self.mode == 'AI task' else (440 if compact else 660)))
            for view, frame in self.base_frames:
                if view not in (self.scroll, self.footer, self.copy_button, self.dry_button):
                    view.setFrameOrigin_((frame.origin.x, frame.origin.y - (180 if self.mode == 'AI task' else (220 if compact else 0))))
            self.details_button.setTitle_('Show details')
            self.home_button.setTitle_('Review only...' if self.mode == 'AI task' else 'Test managed guard')
            self.showing_check_details = False
            self.dry_button.setHidden_(self.mode != 'AI task')
            self.dry_button.setEnabled_(self.review_flow.pending is not None)
            workspace = self.mode == 'Workspace'
            for view in self.workspace_views:
                view.setHidden_(not workspace)
            for view in self.top_views:
                view.setHidden_(workspace)
            details = self.mode not in ('Status', 'Safety check', 'AI task', 'Workspace')
            for view in self.top_views:
                view.setHidden_(not details)
            self.scroll.setFrame_(NSMakeRect(18, 48, 554, 120 if workspace else (240 if self.mode == 'AI task' else (350 if details else 250))))
            if self.mode == 'AI task':
                self.results.setString_(check_summary(getattr(self, 'last_model', 'PAID EXECUTION PAUSED\n\nReview only shows the built-in synthetic source and task. It cannot start a model or worker.\n\nAfter closing review, a separate Check start - no spend button checks a one-use source/task binding. That check also cannot spend.\n\nThe earlier approval-screen cause is unresolved. No paid re-enable from this check.')));return
            if self.mode == 'Safety check':
                self.results.setString_(check_summary(getattr(self, 'last_check', 'Not checked yet.\n\nTest a scripted workload: allow a safe task, block a forbidden request, then stop and remove its container.\n\nNo private files, network or AI credits. Not an intelligent AI agent.')));return
            if workspace:
                self.results.setString_('Offline scratch only. Run the complete check first. No cloud agent is installed.');return
            try:
                from native_overview import section_text
                self.results.setString_(section_text(self.mode))
            except Exception as exc:
                self.showError_('Details unavailable (' + type(exc).__name__ + '). No model call was made.')

        def detailsClicked_(self, _sender):
            if self.busy:
                return
            if self.mode in ('Safety check', 'AI task'):
                self.showing_check_details = not self.showing_check_details
                text = getattr(self, 'last_model' if self.mode == 'AI task' else 'last_check', 'No test result yet.')
                self.results.setString_(text if self.showing_check_details else check_summary(text))
                self.details_button.setTitle_('Hide details' if self.showing_check_details else 'Show details')
            else:
                self.sectionChanged_(None)

        def copyClicked_(self, _sender):
            board = NSPasteboard.generalPasteboard()
            board.clearContents()
            board.setString_forType_(str(self.results.string()), NSPasteboardTypeString)

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
            # Legacy callback stays inert even if invoked without its disabled button.
            self.showError_('Native paid AI tasks and demos are paused. Nothing started.')
            return

        def setBusy_(self, value):
            self.busy = bool(value)
            self.home_button.setEnabled_(not self.busy)
            self.sections.setEnabled_(not self.busy)
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

        @objc.python_method
        def startWorker_(self, operation, kind='workspace'):
            require_offline_native_operation(kind)
            self.operation_kind = kind
            self.setBusy_(True)
            self.download = None
            self.headline.setStringValue_('Checking... please wait for the result and cleanup.')
            self.results.setString_('Running in a disposable offline workspace.\nSupervising the owned workload, applying policy, then verifying cleanup.\n\nKeep SwarmGuard open. No network or AI credits are used by offline checks.')
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
            self.results.setString_(check_summary(str(message)) if self.operation_kind in ('check', 'model') else str(message))
            if self.operation_kind == 'model':
                self.last_model = str(message)
                self.showing_check_details = False
                self.details_button.setTitle_('Show details')
            if self.operation_kind == 'check':
                self.last_check = str(message)
                self.showing_check_details = False
                self.details_button.setTitle_('Show details')
            self.headline.setStringValue_('Finished. Review the result below before continuing.')
            self.setBusy_(False)

        def modelProgress_(self, text):
            if self.busy and self.operation_kind == 'model':
                self.headline.setStringValue_(str(text).split('\n')[0])
                self.results.setString_(str(self.results.string()) + '\n' + str(text))

        def modelClicked_(self, _sender):
            if self.busy:
                return
            # REVIEW ONLY: deliberately no preflight, subprocess or model imports.
            from native_model_task import SOURCE, TASK
            self.review_flow.begin_review()
            self.review_receipt = None
            self.execution_ticket = None
            self.dry_button.setEnabled_(False)
            from execution_gate import Coordinator
            try:
                if self.execution_gate is None:
                    self.execution_gate = Coordinator(Path.home() / 'Library' / 'Application Support' / 'SwarmGuard' / 'dry-execution.sqlite3')
                self.execution_gate.cancel()
            except Exception:
                self.showError_('Cannot record the nonpaying review. Nothing started.');return
            review = NSAlert.alloc().init()
            review.setIcon_(self.brand_icon)
            review.setMessageText_('Review only - paid execution is paused')
            review.setInformativeText_('Closing this screen cannot approve spending or start a task. The next control is a separate nonpaying check.')
            review_scroll = NSScrollView.alloc().initWithFrame_(NSMakeRect(0, 0, 490, 240))
            review_scroll.setHasVerticalScroller_(True)
            review_text = NSTextView.alloc().initWithFrame_(NSMakeRect(0, 0, 470, 240))
            review_text.setEditable_(False);review_text.setSelectable_(True)
            review_text.setString_('TASK:\n' + TASK + '\n\nSYNTHETIC SOURCE sales.txt:\n' + SOURCE.decode() + '\n\nNo real files, keys or account data. A review receipt is not paid authority.')
            review_text.setVerticallyResizable_(True)
            review_text.setHorizontallyResizable_(False)
            review_text.textContainer().setWidthTracksTextView_(True)
            review_scroll.setDocumentView_(review_text)
            review.setAccessoryView_(review_scroll)
            review.addButtonWithTitle_('Close review - no task')
            # No modal return code can route to a paid operation.
            review.runModal()
            try:
                self.execution_ticket = self.execution_gate.review(dry_manifest())
            except Exception:
                self.showError_('Cannot record the nonpaying review. Nothing started.');return
            self.review_receipt = self.review_flow.reviewed({'sales.txt': SOURCE}, TASK)
            self.dry_button.setEnabled_(True)
            self.last_model = ('Review closed. Nothing ran. No credits used.\n'
                               'Separate Check start - no spend is now available once.\n'
                               'Paid execution remains paused.\n\nEvidence:\n' +
                               json.dumps(self.review_flow.audit, indent=2))
            self.results.setString_(check_summary(self.last_model))
            self.headline.setStringValue_('Reviewed only. No model or worker started.')

        def dryStartClicked_(self, _sender):
            if self.busy:
                return
            from native_model_task import SOURCE, TASK
            try:
                manifest = dry_manifest()
                self.execution_gate.decide_dry(self.execution_ticket, manifest, explicit_start=True)
                event = self.execution_gate.dispatch_dry(self.execution_ticket, manifest,
                    lambda claim: self.review_flow.consume_dry(self.review_receipt, {'sales.txt': SOURCE}, TASK))
                self.last_model = ('Nonpaying start check passed.\n'
                                   'Review matched this source and task; one-use receipt consumed.\n'
                                   'Model requests: 0. Worker started: No.\n'
                                   'This is not a live task or a spending approval. Paid execution stays paused.\n\nEvidence:\n' +
                                   json.dumps(self.review_flow.audit, indent=2))
                self.results.setString_(check_summary(self.last_model))
                self.headline.setStringValue_('Nonpaying check finished. Nothing ran.')
            except PermissionError as exc:
                self.showError_(str(exc))
            except Exception:
                self.showError_('Cannot commit the nonpaying check. Nothing started. Do not retry without a new review.')
            finally:
                self.execution_ticket = None
                self.review_receipt = None
                self.dry_button.setEnabled_(False)

        def guardClicked_(self, _sender):
            if self.busy:
                return
            if self.mode == 'AI task':
                self.modelClicked_(None);return
            self.sections.selectItemWithTitle_('Safety check')
            self.sectionChanged_(None)
            def operation():
                from managed_guard import prove_intervention
                result = prove_intervention()
                text = ['Safety check passed.' if result['proof_passed'] else 'Safety check needs attention.',
                        'Scripted workload. Real blocking and container cleanup.',
                        ('A safe file task ran. The forbidden file request was blocked.' if result['proof_passed'] else 'The check did not verify every required step. Review details.'),
                        'Container stopped: ' + ('Yes' if result['stopped'] else 'No'),
                        'Container removed: ' + ('Yes' if result['removed'] else 'No'),
                        'Not an intelligent AI agent or whole-Mac protection.', '', 'Evidence:']
                text.extend(event['kind'] + ': ' + json.dumps({k:v for k,v in event.items() if k != 'kind'}) for event in result['events'])
                if not result['removed']:
                    text.append('Cleanup needs attention: ' + result['name'])
                text.append('Next: review this result. No private host files were requested by a real tool; the denied path was synthetic protocol data.')
                return '\n'.join(text), None
            self.startWorker_(operation, kind='check')

        def checkClicked_(self, _sender):
            if self.busy:
                return
            self.sections.selectItemWithTitle_('Safety check')
            self.sectionChanged_(None)
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
                lines.insert(0, 'Safety check passed.' if result['passed'] else 'Safety check needs attention.')
                lines.append('Next: choose Workspace to run on selected source copies.' if result['passed'] else 'Next: leave your project unchanged. Send this result for help; do not bypass restrictions.')
                lines.extend(['Checked: ' + result['checked_at'], 'Not whole-Mac protection. No installed cloud agent.'])
                return '\n'.join(lines), None
            self.startWorker_(operation, kind='check')

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
