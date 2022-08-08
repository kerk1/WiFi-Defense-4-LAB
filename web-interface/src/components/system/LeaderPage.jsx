import React from 'react'

import Metrics from './leadermetrics/Metrics'

class LeaderPage extends React.Component {
  render () {
    return (
            <div>
                <div className="row">
                    <div className="col-md-12">
                        <h1>Leader</h1>
                    </div>
                </div>

                <div className="row mt-3">
                    <div className="col-md-12">
                        <div className="card">
                            <div className="card-body">
                                <Metrics />
                            </div>
                        </div>
                    </div>
                </div>
            </div>
    )
  }
}

export default LeaderPage;
