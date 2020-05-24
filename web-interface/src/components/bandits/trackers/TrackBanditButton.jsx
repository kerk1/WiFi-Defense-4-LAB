import React from 'react';
import Reflux from 'reflux';

class TrackBanditButton extends Reflux.Component {

    render() {
        const bandit = this.props.bandit;
        const tracker = this.props.tracker;

        let tracking;
        if (tracker.state === "DARK" || tracker.has_pending_tracking_requests) {
            tracking = true;
        } else {
            if (tracker.tracking_mode) {
                tracking = true;
            } else {
                tracking = false;
            }
        }

        if (bandit) {
            if (!tracking) {
                return <button className="btn btn-sm btn-primary" disabled={tracker.has_pending_tracking_requests} onClick={this.props.onStartTrackingClick}>Track This Bandit</button>
            } else {
                return <button className="btn btn-sm btn-warning" disabled={tracker.has_pending_tracking_requests} onClick={this.props.onCancelTrackingClick}>Cancel Tracking</button>
            }
        } else {
            return <span />
        }
    }

}

export default TrackBanditButton;