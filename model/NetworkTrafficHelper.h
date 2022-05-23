#pragma once
#include <deque>
#include <QDebug>

class NetworkTrafficHelper
{
public:
	long timestamp;

	QList<int> speedPoints;

	unsigned int traffic = 0;

	void addPoint(unsigned int updatedTraffic) {
		if (speedPoints.size() > 50) {
			speedPoints.pop_front();
		}
		speedPoints.push_back(updatedTraffic);
		this->traffic = updatedTraffic;
	}
};

