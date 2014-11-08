/****************************************************************************
** Meta object code from reading C++ file 'dialog.h'
**
** Created: Sat Nov 8 03:07:01 2014
**      by: The Qt Meta Object Compiler version 61 (Qt 4.5.1)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "dialog.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'dialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 61
#error "This file was generated using the moc from 4.5.1. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_Dialog[] = {

 // content:
       2,       // revision
       0,       // classname
       0,    0, // classinfo
       6,   12, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors

 // slots: signature, parameters, type, tag, flags
       8,    7,    7,    7, 0x0a,
      19,    7,    7,    7, 0x0a,
      27,    7,    7,    7, 0x0a,
      39,    7,    7,    7, 0x0a,
      48,    7,    7,    7, 0x0a,
      56,    7,    7,    7, 0x0a,

       0        // eod
};

static const char qt_meta_stringdata_Dialog[] = {
    "Dialog\0\0processF()\0stopF()\0addResult()\0"
    "clearF()\0saveF()\0aboutF()\0"
};

const QMetaObject Dialog::staticMetaObject = {
    { &QDialog::staticMetaObject, qt_meta_stringdata_Dialog,
      qt_meta_data_Dialog, 0 }
};

const QMetaObject *Dialog::metaObject() const
{
    return &staticMetaObject;
}

void *Dialog::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_Dialog))
        return static_cast<void*>(const_cast< Dialog*>(this));
    return QDialog::qt_metacast(_clname);
}

int Dialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        switch (_id) {
        case 0: processF(); break;
        case 1: stopF(); break;
        case 2: addResult(); break;
        case 3: clearF(); break;
        case 4: saveF(); break;
        case 5: aboutF(); break;
        default: ;
        }
        _id -= 6;
    }
    return _id;
}
QT_END_MOC_NAMESPACE
