#include "dialog.h"
#include "ui_dialog.h"

//This .cpp file implements User Interface (UI)

Dialog::Dialog(QWidget *parent)
    : QDialog(parent), ui(new Ui::Dialog)
{
    ui->setupUi(this);

    QFont font("Courier", 8, QFont::Normal);
    QFont font1("Times",10, QFont::Normal);

    result=new QTextEdit();
    resultL=new QLabel("Results:");
    trafficL=new QLabel("Traffic:");
    chooseL=new QLabel("Choose interface:");

    processB=new QPushButton("Capture");
    stopB=new QPushButton("Stop");
    clearB=new QPushButton("Clear");
    saveB=new QPushButton("Save as");
    aboutB=new QPushButton("About");

    int w=700,h=200;
    int ht=150;

    sniffer=new SNIFFER();
    sniffer->setFixedSize(w,h);

    //main->addWidget(p);
    result->setFixedSize(w,ht);
    result->setFont(font);

    QGridLayout *panel=new QGridLayout;

    intface=new QComboBox();
    intface->setFixedWidth(w*2/3);


    pcap_if_t *alldevsp;

    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevsp,errbuf)<0)
    {
        result->append(errbuf);
    }
    else
    {
        ifacecount=0;
        while (alldevsp!=NULL)
        {
            intface->addItem(alldevsp->name);
            ifaces[ifacecount]=alldevsp->name;
            ifacecount++;
            alldevsp=alldevsp->next;
        }
    }

    panel->addWidget(chooseL,0,0,1,1,Qt::AlignCenter);
    panel->addWidget(intface,0,1,1,3,Qt::AlignCenter);
    panel->addWidget(processB,1,0,1,1,Qt::AlignCenter);
    panel->addWidget(stopB,1,1,1,1,Qt::AlignCenter);
    panel->addWidget(clearB,1,2,1,1,Qt::AlignCenter);
    panel->addWidget(saveB,1,3,1,1,Qt::AlignCenter);
    panel->addWidget(trafficL,2,0,1,4,Qt::AlignCenter);
    panel->addWidget(sniffer,3,0,1,4,Qt::AlignCenter);
    panel->addWidget(resultL,4,0,1,4,Qt::AlignCenter);
    panel->addWidget(result,5,0,1,4,Qt::AlignCenter);
    panel->addWidget(aboutB,7,0,1,4,Qt::AlignCenter);



    QVBoxLayout *bottom=new QVBoxLayout;
    //bottom->addStretch();
    bottom->addLayout(panel);
    bottom->addStretch();
    QObject::connect(processB,SIGNAL(clicked()),this,
                     SLOT(processF()));
    QObject::connect(stopB,SIGNAL(clicked()),this,
                     SLOT(stopF()));
    QObject::connect(clearB,SIGNAL(clicked()),this,
                     SLOT(clearF()));
    QObject::connect(saveB,SIGNAL(clicked()),this,
                     SLOT(saveF()));
    QObject::connect(aboutB,SIGNAL(clicked()),this,
                     SLOT(aboutF()));
    QObject::connect(sniffer,SIGNAL(onLoad()),this,SLOT(addResult()));


    Dialog::setLayout(bottom);

    timer = new QTimer(this);
    QObject::connect(timer, SIGNAL(timeout()), sniffer, SLOT(update()));
    timer->start(50);
}

Dialog::~Dialog()
{
    delete ui;
}

void Dialog::processF()
{
    //result->append(QString::number(intface->currentIndex(),10));
    if (ifacecount==0)
    {
        sniffer->open(NULL);
    }
    else
        sniffer->open(ifaces[intface->currentIndex()]);
}

void Dialog::addResult()
{
    QString resstring;
    if (sniffer->error)
    {
        resstring="<font color=red>"+sniffer->result+"</font>";
        result->append(resstring);
    }
    else
        result->append(sniffer->result);
}

void Dialog::stopF()
{
    sniffer->close();
}

void Dialog::clearF()
{
    sniffer->clear();
}

void Dialog::saveF()
{

    QString fileName = QFileDialog::getSaveFileName(this,
                 tr("Save File"),
                 "logs/traffic.txt",tr("Text"));
    sniffer->save(fileName);
}

void Dialog::aboutF()
{
    QMessageBox msgBox;
    QFont font("Times", 8, QFont::Normal);
    msgBox.setWindowTitle("About");
    msgBox.setFont(font);
    msgBox.setFixedWidth(700);
    msgBox.setText("<center>Copyright by Andrey Konin</center>"
                   "<center><a href=http://www.akonin.com>www.AKonin.com</a></center>");
    msgBox.exec();
}
