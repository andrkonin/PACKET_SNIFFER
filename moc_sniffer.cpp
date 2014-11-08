/****************************************************************************
** Meta object code from reading C++ file 'sniffer.h'
**
** Created: Sat Nov 8 03:07:03 2014
**      by: The Qt Meta Object Compiler version 61 (Qt 4.5.1)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "sniffer.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'sniffer.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 61
#error "This file was generated using the moc from 4.5.1. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_SNIFFER[] = {

 // content:
       2,       // revision
       0,       // classname
       0,    0, // classinfo
       6,   12, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors

 // signals: signature, parameters, type, tag, flags
       9,    8,    8,    8, 0x05,

 // slots: signature, parameters, type, tag, flags
      24,   18,    8,    8, 0x0a,
      36,    8,    8,    8, 0x0a,
      44,    8,    8,    8, 0x0a,
      53,    8,    8,    8, 0x0a,
      70,   61,    8,    8, 0x0a,

       0        // eod
};

static const char qt_meta_stringdata_SNIFFER[] = {
    "SNIFFER\0\0onLoad()\0INAME\0open(char*)\0"
    "close()\0update()\0clear()\0fileName\0"
    "save(QString)\0"
};

const QMetaObject SNIFFER::staticMetaObject = {
    { &QMainWindow::staticMetaObject, qt_meta_stringdata_SNIFFER,
      qt_meta_data_SNIFFER, 0 }
};

const QMetaObject *SNIFFER::metaObject() const
{
    return &staticMetaObject;
}

void *SNIFFER::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_SNIFFER))
        return static_cast<void*>(const_cast< SNIFFER*>(this));
    return QMainWindow::qt_metacast(_clname);
}

int SNIFFER::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QMainWindow::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        switch (_id) {
        case 0: onLoad(); break;
        case 1: open((*reinterpret_cast< char*(*)>(_a[1]))); break;
        case 2: close(); break;
        case 3: update(); break;
        case 4: clear(); break;
        case 5: save((*reinterpret_cast< QString(*)>(_a[1]))); break;
        default: ;
        }
        _id -= 6;
    }
    return _id;
}

// SIGNAL 0
void SNIFFER::onLoad()
{
    QMetaObject::activate(this, &staticMetaObject, 0, 0);
}
QT_END_MOC_NAMESPACE
