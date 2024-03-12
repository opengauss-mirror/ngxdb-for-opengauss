#ifndef LOGIN_H
#define LOGIN_H

#include <QDialog>
#include <QString>
#include <QMessageBox>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QJsonArray>

namespace Ui {
class Login;
}

class Login : public QDialog
{
    Q_OBJECT

public:
    explicit Login(QWidget *parent = nullptr);
    ~Login();
    QString token="";
    QJsonObject oper;
    QJsonArray actions;
    void init();
    char *url="http://192.168.1.96/func";

private slots:
    void on_pushButtonOK_clicked();

    void on_pushButtonQuit_clicked();

private:
    Ui::Login *ui;
};

#endif // LOGIN_H
