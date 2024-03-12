#include "mainwindow.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    if (w.init()==-1)
       a.quit();
    else
       return a.exec();
}
