#include "login.h"
#include "ui_login.h"
#include "conn.h"


Login::Login(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Login)
{
    ui->setupUi(this);
}

Login::~Login()
{
    delete ui;
}

void Login::init() {
//    int re=ngxdb.init("host=192.168.1.96 dbname=postgres user=conn password=Gao@12345 port=5432");
//    if (re!=CONNECTION_OK) {
//        QMessageBox::information(this,QObject::tr("提示"),QObject::tr("连接服务器失败！"),QMessageBox::Ok,QMessageBox::Ok);
//        close();
//    }
    ngxdb.seturl(url);
    exec();
}

void Login::on_pushButtonOK_clicked()
{
    QString params="loginname="+ui->lineEditUser->text()+"&pass="+ui->lineEditPass->text()+"&system=100";
    char* re=ngxdb.get("/sysinfo/login",params.toLatin1().data());
    if (re==nullptr) {
        QMessageBox::information(this,QObject::tr("提示"),QObject::tr("连接失败！"),QMessageBox::Ok,QMessageBox::Ok);
    } else {
        qDebug()<<"replay"<<re;

        QJsonDocument qj=QJsonDocument::fromJson(QString::fromUtf8(re).toUtf8());
        if (!qj.isNull()) {
            QJsonObject ro=qj.object();
            if (ro.value("errorcode").toInt()!=0) {
                QMessageBox::information(this,QObject::tr("提示"),ro.value("message").toString(),QMessageBox::Ok,QMessageBox::Ok);
            } else {
                ro=ro.value("info").toObject();
                token=ro.value("token").toString();
                oper=ro.value("operator").toObject();
                actions=ro.value("actions").toArray();
                QMessageBox::information(this,QObject::tr("提示"),QObject::tr("登录成功！"),QMessageBox::Ok,QMessageBox::Ok);
                hide();
            }
        } else {
            QMessageBox::information(this,QObject::tr("提示"),QObject::tr("网络出错！"),QMessageBox::Ok,QMessageBox::Ok);
        }
    }
}

void Login::on_pushButton_2_clicked()
{
    close();
}
