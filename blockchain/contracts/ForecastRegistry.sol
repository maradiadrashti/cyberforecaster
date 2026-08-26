// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ForecastRegistry {
    struct ForecastRecord {
        string forecastId;
        string hostIp;
        string predictedStage;
        string dataHash;
        uint256 timestamp;
        uint256 blockNumber;
    }

    // Mapping from forecastId to ForecastRecord
    mapping(string => ForecastRecord) private forecasts;
    
    // Event emitted when a forecast is logged
    event ForecastLogged(
        string indexed forecastId,
        string hostIp,
        string predictedStage,
        string dataHash,
        uint256 timestamp
    );

    // Logs a forecast onto the blockchain
    function logForecast(
        string calldata forecastId,
        string calldata hostIp,
        string calldata predictedStage,
        string calldata dataHash
    ) external {
        // Require that it hasn't been logged already
        require(forecasts[forecastId].timestamp == 0, "Forecast ID already registered");

        forecasts[forecastId] = ForecastRecord({
            forecastId: forecastId,
            hostIp: hostIp,
            predictedStage: predictedStage,
            dataHash: dataHash,
            timestamp: block.timestamp,
            blockNumber: block.number
        });

        emit ForecastLogged(forecastId, hostIp, predictedStage, dataHash, block.timestamp);
    }

    // Retrieves a logged forecast
    function getForecast(string calldata forecastId)
        external
        view
        returns (
            string memory hostIp,
            string memory predictedStage,
            string memory dataHash,
            uint256 timestamp,
            uint256 blockNumber
        )
    {
        ForecastRecord memory record = forecasts[forecastId];
        require(record.timestamp > 0, "Forecast ID not found");
        return (
            record.hostIp,
            record.predictedStage,
            record.dataHash,
            record.timestamp,
            record.blockNumber
        );
    }
}
