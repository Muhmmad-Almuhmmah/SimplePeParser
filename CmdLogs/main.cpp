/***
 * -------------------------------------------------
#
# Project created by QtCreator 2021-6-23T8:31:19
# written By Muhammad Almuhmmah
#
-------------------------------------------------
***/
#include <iostream>
#include <windows.h>
#include <Logs.h>
int main(){
    LOG::resizeWindow(80,45);
    LOG::customText("Hi how are you",25);
    LOG::la("Hello world");
    LOG::lp("Qt");
    LOG::le("000000DD");
    LOG::customText("Hi fdsssssssssssssss are you",25);
    LOG::la("Hello world");
    LOG::lpe("Qt");
    LOG::customText("Hello",25);
    return 0;
}
