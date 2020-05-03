#pragma once

#include <memory>

// Forward declare scan node
class ScanNode;

class ScanAssociation {
	std::shared_ptr<ScanNode> child;

	double PrimaryAssociation;
	double SecondaryAssociation;

public:
	ScanAssociation(std::shared_ptr<ScanNode>& child, double Association);
	ScanAssociation(std::shared_ptr<ScanNode>& child, double PrimaryAssociation, double SecondaryAssociation);
};