#pragma once
#include "ConnectionsModel.h"
#include <QList>
#include <deque>
#include <QDebug>

ConnectionsModel::ConnectionsModel(QObject* parent)
    : QAbstractTableModel(parent)
{
}

void ConnectionsModel::setModel()
{
}

void ConnectionsModel::updateModel(std::vector<ConnDataObj> connectionList)
{
    beginResetModel();
    this->connectionList = connectionList;
    endResetModel();
}

int ConnectionsModel::rowCount(const QModelIndex& /*parent*/) const
{
    return connectionList.size();
}

int ConnectionsModel::columnCount(const QModelIndex& /*parent*/) const
{
    return 8;
}

QVariant ConnectionsModel::data(const QModelIndex& index, int role) const
{
    int row = index.row();
    int col = index.column();

    if (row > connectionList.size())
        return QVariant();

    ConnDataObj currentObj = connectionList[row];

    //auto txValue = ;
    NetworkTrafficHelper helper;
    if (mapDelegate->count(currentObj.localPort)) {
        helper = mapDelegate->at(currentObj.localPort);
    }
    
    if (role == Qt::DisplayRole)
        switch (col) {
        case 0:
            return QString::fromStdString(currentObj.procName);
        case 1:
            return currentObj.pid;
        case 2:
            return QString::fromStdString(currentObj.localAddr);
        case 3:
            return QString::number(currentObj.localPort) + " " + QString::fromStdString(currentObj.localProto);
        case 4:
            return QString::fromStdString(currentObj.remoteAddr) + " " + QString::fromStdString(currentObj.remoteName);
        case 5:
            return QString::number(currentObj.remotePort) + " " + QString::fromStdString(currentObj.remoteProtocol);
        case 6:
            return QString::number(helper.traffic); // here we get the tx speed
        }

    if (role == Qt::UserRole) {
        return QVariant::fromValue(helper.speedPoints);
    }

    return QVariant();
}

QVariant ConnectionsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role == Qt::DisplayRole && orientation == Qt::Horizontal) {
        switch (section) {
        case 0:
            return QString("Owner");
        case 1:
            return QString("PID");
        case 2:
            return QString("Local Addr");
        case 3:
            return QString("Local Port");
        case 4:
            return QString("Remote Address");
        case 5:
            return QString("Remote Port");
        case 6:
            return QString("Transfer speed(bits/sec)");
        }
    }
    return QVariant();
}

void ConnectionsModel::setMapDelegate(std::unordered_map<uint16_t, NetworkTrafficHelper>* portBytes_map)
{
    this->mapDelegate = portBytes_map;
}
