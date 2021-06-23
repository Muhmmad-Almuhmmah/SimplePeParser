/***
 * -------------------------------------------------
#
# Project created by QtCreator 2021-6-23T8:31:19
# written By Muhammad Almuhmmah
#
-------------------------------------------------
***/
#ifndef LOGS_H
#define LOGS_H

#include <QDebug>
#include <QThread>
#include <windows.h>
#include <process.h>
#include <Tlhelp32.h>
#include <winbase.h>
#include <iostream>
#include <fstream>
#include <iomanip>

using namespace std;
#define sleep(x) QThread::msleep(x)

HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
class LOG
{
public:
    LOG() {}
    static void resizeWindow(short h,short w,bool LockResize=true){
        SMALL_RECT WinRect = {0, 0, h,w};
        SetConsoleWindowInfo(GetStdHandle(STD_OUTPUT_HANDLE), true, &WinRect);
        if(LockResize){
            HWND consoleWindow = GetConsoleWindow();
            SetWindowLong(consoleWindow, GWL_STYLE, GetWindowLong(consoleWindow, GWL_STYLE) & ~WS_MAXIMIZEBOX & ~WS_SIZEBOX);
        }
    }
    static void la(QString commant,int i=0)
    {
        SetColor(15);
        if(i==0)
            cout <<commant.toStdString()<<" : ";
        else
            cout <<commant.toStdString();
    }

    static void lp(const QString &result)
    {
        SetColor(9);
        cout <<result.toStdString()<<std::endl;
    }

    static void lpe(const QString &result)
    {
        SetColor(12);
        cout <<result.toStdString()<<std::endl;
    }

    static void le(const QString &commant)
    {
        SetColor(12);
        cout <<commant.toStdString()<<std::endl;
    }
    static void SetColor(int colorID){
        SetConsoleTextAttribute(hConsole, colorID);
    }
    static void customText(const QString &title,int widthSpace=20)
    {
        SetColor(10);
        int len=25;
        if(title.length()<len)
            len-=title.length();
        else
            len=3;
        QString fSpace,tSpace;
        fSpace=fSpace.fill(0x20,widthSpace);
        tSpace=tSpace.fill(0x20,len/2);
        cout << QString("%1.....:: %2%3%2 ::.....").arg(fSpace).arg(tSpace).arg(title).toStdString()<<endl;
        SetColor(15);
    }

    static void die(const char *format, ...) {
        SetColor(9);
        char *buf = (char*) malloc(4096);
        ZeroMemory(buf,4096);
        va_list argList;
        va_start(argList, format);
        vsnprintf(buf, 4096,format, argList);
        va_end(argList);
        cout <<buf<<endl;
    }
    static void dieError(const char* fmt, ...) {
        SetColor(12);
        va_list ap;
        va_start(ap, fmt);
        fprintf(stdout, "Error: ");
        vfprintf(stdout, fmt, ap);
        fprintf(stdout, "\n");
        va_end(ap);
        LOG::SetColor(7);//white ...default color
        //        exit(EXIT_FAILURE);
    }


};
#endif // LOGS_H
