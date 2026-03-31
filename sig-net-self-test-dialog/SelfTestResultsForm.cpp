//==============================================================================
// Sig-Net Library Self-Test Results Dialog - Implementation
//==============================================================================

#include <vcl.h>
#pragma hdrstop

#include "SelfTestResultsForm.h"
#include <Clipbrd.hpp>

#pragma resource "*.dfm"
TSelfTestResultsForm* SelfTestResultsForm;

//==============================================================================
// Constructor/Destructor
//==============================================================================

__fastcall TSelfTestResultsForm::TSelfTestResultsForm(TComponent* Owner)
    : TForm(Owner), tests_have_run(false) {
    
    // Form properties
    Caption = "Sig-Net Library Self-Test Results";
    Position = poMainFormCenter;
    Width = 800;
    Height = 600;
    BorderStyle = bsDialog;
    Font->Name = "Segoe UI";
    Font->Size = 10;
    
    // === HEADER PANEL ===
    PanelHeader = new TPanel(this);
    PanelHeader->Parent = this;
    PanelHeader->Align = alTop;
    PanelHeader->Height = 70;
    PanelHeader->BevelOuter = bvNone;
    PanelHeader->Color = static_cast<TColor>(0xF0F0F0);
    PanelHeader->Padding->SetBounds(10, 10, 10, 10);
    
    LabelTitle = new TLabel(this);
    LabelTitle->Parent = PanelHeader;
    LabelTitle->Left = 10;
    LabelTitle->Top = 10;
    LabelTitle->Caption = "Sig-Net Library Self-Tests";
    LabelTitle->Font->Size = 14;
    LabelTitle->Font->Style = TFontStyles() << fsBold;
    
    LabelStats = new TLabel(this);
    LabelStats->Parent = PanelHeader;
    LabelStats->Left = 10;
    LabelStats->Top = 35;
    LabelStats->Caption = "Test results will appear below...";
    LabelStats->Font->Size = 10;
    LabelStats->Font->Color = static_cast<TColor>(0x666666);
    
    // === RESULTS PANEL (with grid) ===
    PanelResults = new TPanel(this);
    PanelResults->Parent = this;
    PanelResults->Align = alClient;
    PanelResults->BevelOuter = bvNone;
    PanelResults->Padding->SetBounds(10, 10, 10, 10);
    
    GridResults = new TStringGrid(this);
    GridResults->Parent = PanelResults;
    GridResults->Align = alClient;
    GridResults->RowCount = 1;
    GridResults->ColCount = 3;
    GridResults->DefaultRowHeight = 24;
    GridResults->Options << goRowSelect << goThumbTracking << goVertLine << goHorzLine;
    GridResults->OnDrawCell = GridResultsDrawCell;
    
    // Setup grid columns
    GridResults->ColWidths[0] = 40;   // Status indicator
    GridResults->ColWidths[1] = 400;  // Test name
    GridResults->ColWidths[2] = 300;  // Error message
    
    // Header row
    GridResults->Cells[0][0] = " ";
    GridResults->Cells[1][0] = "Test Name";
    GridResults->Cells[2][0] = "Details";
    
    // === BUTTONS PANEL ===
    PanelButtons = new TPanel(this);
    PanelButtons->Parent = this;
    PanelButtons->Align = alBottom;
    PanelButtons->Height = 50;
    PanelButtons->BevelOuter = bvNone;
    PanelButtons->Padding->SetBounds(10, 10, 10, 10);
    
    ButtonRunTests = new TButton(this);
    ButtonRunTests->Parent = PanelButtons;
    ButtonRunTests->Caption = "Run Tests";
    ButtonRunTests->Width = 100;
    ButtonRunTests->Height = 30;
    ButtonRunTests->Left = 10;
    ButtonRunTests->Top = 10;
    ButtonRunTests->OnClick = ButtonRunTestsClick;
    
    ButtonCopyResults = new TButton(this);
    ButtonCopyResults->Parent = PanelButtons;
    ButtonCopyResults->Caption = "Copy Results";
    ButtonCopyResults->Width = 100;
    ButtonCopyResults->Height = 30;
    ButtonCopyResults->Left = 120;
    ButtonCopyResults->Top = 10;
    ButtonCopyResults->OnClick = ButtonCopyResultsClick;
    
    ButtonClose = new TButton(this);
    ButtonClose->Parent = PanelButtons;
    ButtonClose->Caption = "Close";
    ButtonClose->Width = 100;
    ButtonClose->Height = 30;
    ButtonClose->Left = 690;
    ButtonClose->Top = 10;
    ButtonClose->OnClick = ButtonCloseClick;
    ButtonClose->ModalResult = mrCancel;
}

__fastcall TSelfTestResultsForm::~TSelfTestResultsForm() {
    // Destructor (cleanup is automatic with VCL)
}

//==============================================================================
// Event Handlers
//==============================================================================

void __fastcall TSelfTestResultsForm::FormCreate(TObject* Sender) {
    // Form creation
}

void __fastcall TSelfTestResultsForm::FormShow(TObject* Sender) {
    // Form display (optionally auto-run tests on show)
}

void __fastcall TSelfTestResultsForm::ButtonRunTestsClick(TObject* Sender) {
    test_results.Reset();
    
    // Run all tests
    SigNet::SelfTest::RunAllTests(test_results);
    
    tests_have_run = true;
    
    // Update UI
    PopulateGrid();
    UpdateStatistics();
}

void __fastcall TSelfTestResultsForm::ButtonCopyResultsClick(TObject* Sender) {
    AnsiString output;
    
    // Build summary
    output += "Sig-Net Library Self-Test Results\r\n";
    output += "===================================\r\n\r\n";
    output += LabelStats->Caption + "\r\n\r\n";
    
    // Build test details
    output += "Test Results:\r\n";
    output += "-------------\r\n";
    
    for (size_t i = 0; i < test_results.test_count; i++) {
        const SigNet::SelfTest::TestResult& test = test_results.tests[i];
        
        output += (test.passed ? "[PASS] " : "[FAIL] ");
        output += AnsiString(test.name) + "\r\n";
        
        if (!test.passed && test.error_message[0] != '\0') {
            output += "       Error: " + AnsiString(test.error_message) + "\r\n";
        }
    }
    
    // Copy to clipboard
    TClipboard* clipboard = Clipboard();
    clipboard->AsText = output;
    
    ShowMessage("Test results copied to clipboard");
}

void __fastcall TSelfTestResultsForm::ButtonCloseClick(TObject* Sender) {
    Close();
}

void __fastcall TSelfTestResultsForm::GridResultsDrawCell(TObject* Sender, int ACol,
                                                          int ARow, const TRect& ARect,
                                                          TGridDrawState AState) {
    TStringGrid* grid = dynamic_cast<TStringGrid*>(Sender);
    if (!grid) return;
    
    TCanvas* canvas = grid->Canvas;
    
    // Set background colors based on test result
    if (ARow == 0) {
        // Header row
        canvas->Brush->Color = static_cast<TColor>(0xE0E0E0);
        canvas->Font->Style = TFontStyles() << fsBold;
    } else if (ARow > 0 && ARow <= (int)test_results.test_count) {
        const SigNet::SelfTest::TestResult& test = test_results.tests[ARow - 1];
        canvas->Brush->Color = test.passed ? static_cast<TColor>(0xE0F8E0) : static_cast<TColor>(0xF8E0E0);
        canvas->Font->Color = test.passed ? static_cast<TColor>(0x008000) : static_cast<TColor>(0xFF0000);
    }
    
    canvas->FillRect(ARect);
    
    // Draw text
    canvas->TextOut(ARect.Left + 4, ARect.Top + 4, grid->Cells[ACol][ARow]);
}

//==============================================================================
// Private Methods
//==============================================================================

void TSelfTestResultsForm::UpdateTestResults() {
    // Called after tests are run
}

void TSelfTestResultsForm::PopulateGrid() {
    // Set grid size
    GridResults->RowCount = test_results.test_count + 1;
    
    // Fill in test data
    for (size_t i = 0; i < test_results.test_count; i++) {
        const SigNet::SelfTest::TestResult& test = test_results.tests[i];
        
        // Status column
        GridResults->Cells[0][i + 1] = test.passed ? "PASS" : "FAIL";
        
        // Test name column
        GridResults->Cells[1][i + 1] = AnsiString(test.name);
        
        // Error message column
        if (!test.passed && test.error_message[0] != '\0') {
            GridResults->Cells[2][i + 1] = AnsiString(test.error_message);
        } else {
            GridResults->Cells[2][i + 1] = test.passed ? "Passed" : "Failed";
        }
    }
    
    GridResults->Repaint();
}

void TSelfTestResultsForm::UpdateStatistics() {
    char stat_text[256];
    snprintf(stat_text, sizeof(stat_text),
             "Results: %zu passed, %zu failed out of %zu tests",
             test_results.passed_count,
             test_results.failed_count,
             test_results.test_count);
    
    LabelStats->Caption = AnsiString(stat_text);
    
    if (test_results.failed_count == 0) {
        LabelStats->Font->Color = static_cast<TColor>(0x008000);  // Green
    } else {
        LabelStats->Font->Color = static_cast<TColor>(0xFF0000);  // Red
    }
}

//==============================================================================
// EOF
//==============================================================================
