//==============================================================================
// Sig-Net Library Self-Test Results Dialog
//==============================================================================
//
// VCL Dialog Component for displaying Sig-Net library self-test results.
// Can be embedded in any C++Builder VCL application.
//
// Usage:
//   TSelfTestResultsForm* form = new TSelfTestResultsForm(Application);
//   form->ShowModal();
//   delete form;
//
//==============================================================================

#ifndef SelfTestResultsFormH
#define SelfTestResultsFormH

#include <System.Classes.hpp>
#include <Vcl.Controls.hpp>
#include <Vcl.Forms.hpp>
#include <Vcl.Dialogs.hpp>
#include <Vcl.StdCtrls.hpp>
#include <Vcl.ExtCtrls.hpp>
#include <Vcl.Grids.hpp>
#include <Vcl.Graphics.hpp>

// Include Sig-Net library
#include "..\sig-net.hpp"

//==============================================================================
// Self-Test Results Dialog Form
//==============================================================================

class TSelfTestResultsForm : public TForm {
__published:
    // Components
    TPanel* PanelHeader;
    TLabel* LabelTitle;
    TLabel* LabelStats;
    
    TPanel* PanelResults;
    TStringGrid* GridResults;
    
    TPanel* PanelButtons;
    TButton* ButtonRunTests;
    TButton* ButtonCopyResults;
    TButton* ButtonClose;
    
    // Event handlers
    void __fastcall FormCreate(TObject* Sender);
    void __fastcall FormShow(TObject* Sender);
    void __fastcall ButtonRunTestsClick(TObject* Sender);
    void __fastcall ButtonCopyResultsClick(TObject* Sender);
    void __fastcall ButtonCloseClick(TObject* Sender);
    void __fastcall GridResultsDrawCell(TObject* Sender, int ACol, int ARow,
                                        const TRect& ARect, TGridDrawState AState);

private:
    SigNet::SelfTest::TestSuiteResults test_results;
    bool tests_have_run;
    
    void UpdateTestResults();
    void PopulateGrid();
    void UpdateStatistics();
    
public:
    __fastcall TSelfTestResultsForm(TComponent* Owner);
    __fastcall ~TSelfTestResultsForm();
};

extern PACKAGE TSelfTestResultsForm* SelfTestResultsForm;

#endif // SelfTestResultsFormH
