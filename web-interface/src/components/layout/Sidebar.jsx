import React from 'react'
import ApiRoutes from "../../util/ApiRoutes";
import NavigationLink from "./NavigationLink";
import SidebarSubmenu from "./SidebarSubmenu";
import UserProfile from "./UserProfile";

function Sidebar() {

    return (
        <div id="nav-side">
            <p className="brand">
                <a href={ApiRoutes.DASHBOARD} >nzyme</a>
            </p>

            <div className="mt-4 mb-4">
                <UserProfile />
            </div>

            <ul className="nav nav-pills flex-column mb-sm-auto mb-0 align-items-center align-items-sm-start" id="menu">
                <NavigationLink
                    href={ApiRoutes.DASHBOARD}
                    title="Dashboard"
                    icon={<i className="fa-regular fa-map fa-icon" />} />

                <NavigationLink
                    href="/foo/bar"
                    title="Ethernet"
                    icon={<i className="fa-solid fa-network-wired fa-icon" />} />

                <SidebarSubmenu title="WiFi" subhref="/dot11" icon={<i className="fa-solid fa-wifi fa-icon" />}>
                    <NavigationLink
                        href={ApiRoutes.DOT11.NETWORKS.INDEX}
                        title="Networks"
                        icon={<i className="fa-solid fa-list fa-icon" />} />

                    <NavigationLink
                        href={ApiRoutes.DOT11.BANDITS.INDEX}
                        title="Bandits"
                        icon={<i className="fa-solid fa-satellite-dish fa-icon" />} />

                    <NavigationLink
                        href={ApiRoutes.DOT11.ASSETS.INDEX}
                        title="WiFi Assets"
                        icon={<i className="fa-solid fa-clipboard-list fa-icon" />} />
                </SidebarSubmenu>

                <NavigationLink
                    href={ApiRoutes.REPORTING.INDEX}
                    title="Reporting"
                    icon={<i className="fa-solid fa-file-circle-check fa-icon" />} />

                <SidebarSubmenu title="System" subhref="/system" icon={<i className="fa-solid fa-screwdriver-wrench fa-icon" />}>
                    <NavigationLink
                        href={ApiRoutes.SYSTEM.LEADER}
                        title="Leader"
                        icon={<i className="fa-solid fa-stethoscope fa-icon" />} />
                    <NavigationLink
                        href={ApiRoutes.SYSTEM.TAPS.INDEX}
                        title="Taps"
                        icon={<i className="fa-solid fa-circle-nodes fa-icon" />} />
                    <NavigationLink
                        href={ApiRoutes.SYSTEM.AUTHENTICATION}
                        title="Authentication"
                        icon={<i className="fa-solid fa-users fa-icon" />} />
                    <NavigationLink
                        href={ApiRoutes.SYSTEM.VERSION}
                        title="Version"
                        icon={<i className="fa-solid fa-tag fa-icon" />} />
                </SidebarSubmenu>
            </ul>
        </div>
    );

}

export default Sidebar;