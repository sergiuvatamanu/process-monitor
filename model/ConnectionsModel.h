#include <QAbstractListModel>

#include "NetworkTrafficHelper.h"
#include "ConnDataObj.h"
#include <WinSock2.h>
#include <unordered_map>

const int COLS = 12;
const int ROWS = 100;

class ConnectionsModel : public QAbstractTableModel
{
public:
    ConnectionsModel(QObject* parent = nullptr);

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;

    void setMapDelegate(std::unordered_map<uint16_t, NetworkTrafficHelper>* portBytes_map);

    void setModel();
    void updateModel(std::vector<ConnDataObj> connectionList);

private:
    std::unordered_map<uint16_t, NetworkTrafficHelper>* mapDelegate; 
    std::vector<ConnDataObj> connectionList;
    std::unordered_map<uint16_t, QList<int>> traffic_map;
};