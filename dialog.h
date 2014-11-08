#ifndef DIALOG_H
#define DIALOG_H

#include <QtGui/QDialog>
#include <QLineEdit>
#include <QTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QHBoxLayout>
#include <QFileDialog>
#include "sniffer.h"
#include <QMessageBox>
#include <QTimer>
#include <QtGui/QComboBox>
#include <pcap.h>

namespace Ui
{
    class Dialog;
}

class Dialog : public QDialog
{
    Q_OBJECT

public:
    Dialog(QWidget *parent = 0);
    ~Dialog();
    QTimer *timer;
    QTextEdit *result;
    QLabel *trafficL;
    QLabel *resultL;
    QLabel *chooseL;
    SNIFFER *sniffer;
    QLabel *imagelabel;
    QPushButton *processB;
    QPushButton *stopB;
    QPushButton *clearB;
    QPushButton *saveB;
    QPushButton *aboutB;
    QComboBox *intface;

    char *ifaces[10];
    int ifacecount;

public slots:

    void processF();
    void stopF();
    void addResult();
    void clearF();
    void saveF();
    void aboutF();

private:
    Ui::Dialog *ui;

};

#endif // DIALOG_H
