// SPDX-License-Identifier: GPL-2.0
/*
 * Marvell 88Q2XXX automotive 100BASE-T1/1000BASE-T1 PHY driver
 */
#include <linux/ethtool_netlink.h>
#include <linux/marvell_phy.h>
#include <linux/phy.h>

// Link-Up Timeout
#define MRVL_Q212X_LINKUP_TIMEOUT     200

// Single SEND_S Flag: apply to both LP and DUT
#define MRVL_Q212X_SINGLE_SEND_S_ENABLE	1

/* 1000BASE-X/SGMII Status Register */
#define MV_1GBX_STAT            (0x2000 + MII_BMSR)

#define MDIO_MMD_AN_MV_STAT			32769
#define MDIO_MMD_AN_MV_STAT_ANEG		0x0100
#define MDIO_MMD_AN_MV_STAT_LOCAL_RX		0x1000
#define MDIO_MMD_AN_MV_STAT_REMOTE_RX		0x2000
#define MDIO_MMD_AN_MV_STAT_LOCAL_MASTER	0x4000
#define MDIO_MMD_AN_MV_STAT_MS_CONF_FAULT	0x8000

#define MDIO_MMD_PCS_MV_100BT1_STAT1			33032
#define MDIO_MMD_PCS_MV_100BT1_STAT1_IDLE_ERROR	0x00FF
#define MDIO_MMD_PCS_MV_100BT1_STAT1_JABBER		0x0100
#define MDIO_MMD_PCS_MV_100BT1_STAT1_LINK		0x0200
#define MDIO_MMD_PCS_MV_100BT1_STAT1_LOCAL_RX		0x1000
#define MDIO_MMD_PCS_MV_100BT1_STAT1_REMOTE_RX		0x2000
#define MDIO_MMD_PCS_MV_100BT1_STAT1_LOCAL_MASTER	0x4000

#define MDIO_MMD_PCS_MV_100BT1_STAT2		33033
#define MDIO_MMD_PCS_MV_100BT1_STAT2_JABBER	0x0001
#define MDIO_MMD_PCS_MV_100BT1_STAT2_POL	0x0002
#define MDIO_MMD_PCS_MV_100BT1_STAT2_LINK	0x0004
#define MDIO_MMD_PCS_MV_100BT1_STAT2_ANGE	0x0008


struct mv2122_data {
        phy_interface_t line_interface;
        __ETHTOOL_DECLARE_LINK_MODE_MASK(supported);
        bool sfp_link;
};

static int mv88q2xxx_tx_enable(struct phy_device *phydev)
{
	return phy_clear_bits_mmd(phydev, 3 ,0x8000, 0x8);
}

static int mv88q2xxx_tx_disable(struct phy_device *phydev)
{
	return phy_clear_bits_mmd(phydev, 3 ,0x8000, 0x8);
}

static int mv88q2xxx_resume(struct phy_device *phydev)
{
	return mv88q2xxx_tx_enable(phydev);
}

static int mv88q2xxx_suspend(struct phy_device *phydev)
{
	return mv88q2xxx_tx_disable(phydev);
}
static int mv88q2xxx_soft_reset(struct phy_device *phydev)
{
	phy_write_mmd(phydev, MDIO_MMD_PCS, 0x0900, 0x8000);

	return 0;
}

static int get_speed(struct phy_device *phydev)
{
	u16 value = 0;

	if (phydev->autoneg)
		value = (phy_read_mmd(phydev, 7, 0x801a) & 0x4000) >> 14;
	else
		value = (phy_read_mmd(phydev, 1, 0x0834) & 0x1);

	return value ? SPEED_1000 : SPEED_100;
}

static int check_link(struct phy_device *phydev)
{
	u16 ret1, ret2;

	if (phydev->speed == SPEED_1000) {
		ret1 = phy_read_mmd(phydev, 3, 0x0901);
		ret1 = phy_read_mmd(phydev, 3, 0x0901);
		ret2 = phy_read_mmd(phydev, 7, 0x8001);
	} else {
		ret1 = phy_read_mmd(phydev, 3, 0x8109);
		ret2 = phy_read_mmd(phydev, 3, 0x8108);
	}

	return (0x0 != (ret1 & 0x0004)) && (0x0 != (ret2 & 0x3000)) ? 1 : 0;
}

static int read_master_slave(struct phy_device *phydev)
{
	int reg;

	phydev->master_slave_get = MASTER_SLAVE_CFG_UNKNOWN;
	phydev->master_slave_state = MASTER_SLAVE_STATE_UNKNOWN;

	reg = phy_read_mmd(phydev, 7, 0x8001);
	if (reg & (1 << 14)) {
		phydev->master_slave_get = MASTER_SLAVE_CFG_MASTER_FORCE;
		phydev->master_slave_state = MASTER_SLAVE_STATE_MASTER;
	} else {
		phydev->master_slave_get = MASTER_SLAVE_CFG_SLAVE_FORCE;
		phydev->master_slave_state = MASTER_SLAVE_STATE_SLAVE;
	}

	return 0;
}

static int mv88q2xxx_read_status(struct phy_device *phydev)
{
	int ret;
	
	ret = genphy_update_link(phydev);
	if (ret)
		return ret;

	phydev->link = check_link(phydev);
	phydev->speed = get_speed(phydev);

	ret = read_master_slave(phydev);
	if (ret)
		return ret;

	return 0;
}

static int mv88q2xxx_get_features(struct phy_device *phydev)
{
	int ret;

	//All supported features are set at probe
	return 0;
}

static int setup_master_slave(struct phy_device *phydev)
{
	u16 reg_data = phy_read_mmd(phydev, 1, 0x0834);

	switch (phydev->master_slave_set) {
	case MASTER_SLAVE_CFG_MASTER_FORCE:
	case MASTER_SLAVE_CFG_MASTER_PREFERRED:
		reg_data |= 0x4000;
		break;
	case MASTER_SLAVE_CFG_SLAVE_PREFERRED:
	case MASTER_SLAVE_CFG_SLAVE_FORCE:
		reg_data &= ~0x4000;
		break;
	case MASTER_SLAVE_CFG_UNKNOWN:
	case MASTER_SLAVE_CFG_UNSUPPORTED:
		return 0;
	default:
		phydev_warn(phydev, "Unsupported Master/Slave mode\n");
		return -EOPNOTSUPP;
	}

	phy_write_mmd(phydev, 1, 0x0834, reg_data);

	return 0;
}

static int mv88q2xxx_config_aneg(struct phy_device *phydev)
{
	u16 value = phy_read_mmd(phydev, 1, 0x0834);
	u16 reg_data = phy_read_mmd(phydev, 1, 0x0834);

	value = (value & 0xFFF0) | 0x0001;
	phy_write_mmd(phydev, 1, 0x0834, value);

	setup_master_slave(phydev);

        return mv88q2xxx_soft_reset(phydev);
}

static int mv88q2xxx_aneg_done(struct phy_device *phydev)
{
        int ret;

        ret = phy_read_mmd(phydev, MDIO_MMD_PCS, MV_1GBX_STAT);
        if (ret < 0)
                return ret;

        return (ret & BMSR_ANEGCOMPLETE);
}

static int mv88q2xxx_config_init(struct phy_device *phydev)
{
        int ret;
	
	u16 value = phy_read_mmd(phydev, 1, 0x0834);
	u16 reg_data = phy_read_mmd(phydev, 1, 0x0834);

	value = (value & 0xFFF0) | 0x0001;
	phy_write_mmd(phydev, 1, 0x0834, value);

	setup_master_slave(phydev);
	//reset
	mv88q2xxx_soft_reset(phydev);

	return 0;
}

static int mv88q2xxx_probe(struct phy_device *phydev)
{
        struct device *dev = &phydev->mdio.dev;
        struct mv2122_data *priv = NULL;

	printk("phy 2122 detected, Handle probe here.\n");
        __ETHTOOL_DECLARE_LINK_MODE_MASK(supported) = { 0, };

        linkmode_set_bit(ETHTOOL_LINK_MODE_Autoneg_BIT, supported);
        linkmode_set_bit(ETHTOOL_LINK_MODE_Pause_BIT, supported);
        linkmode_set_bit(ETHTOOL_LINK_MODE_Asym_Pause_BIT, supported);
        linkmode_set_bit(ETHTOOL_LINK_MODE_FIBRE_BIT, supported);
        linkmode_set_bit(ETHTOOL_LINK_MODE_TP_BIT, supported);
        linkmode_set_bit(ETHTOOL_LINK_MODE_1000baseT_Half_BIT, supported);
        linkmode_set_bit(ETHTOOL_LINK_MODE_1000baseT_Full_BIT, supported);
        linkmode_set_bit(ETHTOOL_LINK_MODE_1000baseX_Full_BIT, supported);

        linkmode_copy(phydev->supported, supported);

        priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
        if (!priv)
                return -ENOMEM;

        priv->line_interface = PHY_INTERFACE_MODE_NA;
        phydev->priv = priv;

	return 0;
}

static int mv88q2xxxx_get_sqi(struct phy_device *phydev)
{
	int ret;

	/* Read from vendor specific registers, they are not documented
	 * but can be found in the Software Initialization Guide. Only
	 * revisions >= A0 are supported.
	 */
	ret = phy_modify_mmd(phydev, MDIO_MMD_PCS, 0xFC5D, 0x00FF, 0x00AC);
	if (ret < 0)
		return ret;

	ret = phy_read_mmd(phydev, MDIO_MMD_PCS, 0xfc88);
	if (ret < 0)
		return ret;

	return ret & 0x0F;
}

static int mv88q2xxxx_get_sqi_max(struct phy_device *phydev)
{
        return 15;
}
static struct phy_driver mv88q2xxx_driver[] = {
        {
                .phy_id                 = MARVELL_PHY_ID_88Q2110,
                .phy_id_mask            = MARVELL_PHY_ID_MASK,
                .name                   = "mv88q2110",
		.get_features		= mv88q2xxx_get_features,
                .probe                  = mv88q2xxx_probe,
                .soft_reset             = mv88q2xxx_soft_reset,
                .config_init            = mv88q2xxx_config_init,
		.suspend 		= mv88q2xxx_suspend,
		.resume 		= mv88q2xxx_resume,
                .read_status            = mv88q2xxx_read_status,
                .config_aneg            = mv88q2xxx_config_aneg,
		.aneg_done		= mv88q2xxx_aneg_done,
                .get_sqi                = mv88q2xxxx_get_sqi,
                .get_sqi_max            = mv88q2xxxx_get_sqi_max,
        },
        {
                .phy_id                 = MARVELL_PHY_ID_88Q2122,
                .phy_id_mask            = MARVELL_PHY_ID_MASK,
                .name                   = "mv88q2122",
		.get_features		= mv88q2xxx_get_features,
                .probe                  = mv88q2xxx_probe,
                .soft_reset             = mv88q2xxx_soft_reset,
                .config_init            = mv88q2xxx_config_init,
		.suspend 		= mv88q2xxx_suspend,
		.resume 		= mv88q2xxx_resume,
                .read_status            = mv88q2xxx_read_status,
                .config_aneg            = mv88q2xxx_config_aneg,
		.aneg_done		= mv88q2xxx_aneg_done,
                .get_sqi                = mv88q2xxxx_get_sqi,
                .get_sqi_max            = mv88q2xxxx_get_sqi_max,
        }
};

module_phy_driver(mv88q2xxx_driver);

static struct mdio_device_id __maybe_unused mv88q2xxx_tbl[] = {
        { MARVELL_PHY_ID_88Q2110, MARVELL_PHY_ID_MASK },
        { MARVELL_PHY_ID_88Q2122, MARVELL_PHY_ID_MASK },
        { /*sentinel*/ }
};
MODULE_DEVICE_TABLE(mdio, mv88q2xxx_tbl);

MODULE_DESCRIPTION("Marvell 88Q2XXX 100/1000BASE-T1 Automotive Ethernet PHY driver");
MODULE_LICENSE("GPL");
