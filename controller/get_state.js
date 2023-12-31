const indianCitiesDatabase = require('indian-cities-database');
const states = indianCitiesDatabase.cities;

const getState = async (req, res) => {

    const stateList = [];
    for (let i = 0; i < states.length; i++) {
        if (!(stateList.includes(states[i]['state'].toLowerCase()))) {
            stateList.push(states[i]['state'].trim().toLowerCase())
        }
    }

    res.status(200).send({ "state": 200, "message": "State list fetched successfully", "data": stateList });
    return;
}

const getCity = (req, res) => {

    const state = req.query.state;

    const cityList = [];
    for (let i = 0; i < states.length; i++) {
        if (states[i]['state'].toLowerCase() === state.toLowerCase()) {
            cityList.push(states[i]['city'].trim())
        }
    }
    res.status(200).send({ "state": 200, "message": "City list fetched successfully", "data": { "state": state, "cities": cityList } });
    return;

}

module.exports = { getState, getCity }