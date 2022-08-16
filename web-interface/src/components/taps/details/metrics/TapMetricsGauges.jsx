import React from "react";
import numeral from "numeral";
import FormattedGauge from "./FormattedGauge";
import ApiRoutes from "../../../../util/ApiRoutes";

function TapMetricsGauges(props) {

    return (
        <table className="table table-sm table-hover table-striped">
            <thead>
            <tr>
                <th>Gauge</th>
                <th>Value</th>
                <th>&nbsp;</th>
            </tr>
            </thead>
            <tbody>
            {Object.keys(props.gauges).sort((a, b) => a.localeCompare(b)).map(function (key, i) {
                return (
                    <tr key={"metric-gauge-" + i}>
                        <td>{props.gauges[key].metric_name}</td>
                        <td><FormattedGauge name={props.gauges[key].metric_name} value={props.gauges[key].metric_value} /></td>
                        <td>
                            <a href={ApiRoutes.SYSTEM.TAPS.METRICDETAILS(props.tap.name, "gauge", props.gauges[key].metric_name)}>
                                Chart
                            </a>
                        </td>
                    </tr>
                )
            })}
            </tbody>
        </table>
    )

}

export default TapMetricsGauges;