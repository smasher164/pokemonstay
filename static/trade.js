let btnJoin = document.querySelector("#btn-join")
let btnLeave = document.querySelector("#btn-leave")
let btnConfirm = document.querySelector("#btn-confirm")
let btnCancel = document.querySelector("#btn-cancel")
let user1 = document.querySelector("#user1")
let user2 = document.querySelector("#user2")
let pokemon1 = document.querySelector("#pokemon1")
let pokemon2 = document.querySelector("#pokemon2")
let confirm1 = document.querySelector("#confirm1")
let confirm2 = document.querySelector("#confirm2")
let selectBox = document.querySelector("#select-box")

let reNat = /^\d+$/

joinable = true
leavable = false
confirmable = false
cancellable = false
trade = {}
box = []
options = `<option value=""></option>`

let updateUI = () => {
    btnJoin.style.display = joinable ? "" : "none"
    btnLeave.style.display = leavable ? "" : "none"
    user1.textContent = "User 1: " + (trade.user1Id ? trade.user1Id : "")
    user2.textContent = "User 2: " + (trade.user2Id ? trade.user2Id : "")
    pokemon1.textContent = "Pokémon ID 1: " + (trade.pokemon1 ? trade.pokemon1 : "")
    pokemon2.textContent = "Pokémon ID 2: " + (trade.pokemon2 ? trade.pokemon2 : "")
    confirm1.textContent = "Confirm 1: " + Boolean(trade.confirm1)
    confirm1.style.display = trade.user1Id ? "" : "none"
    confirm2.textContent = "Confirm 2: " + Boolean(trade.confirm2)
    confirm2.style.display = trade.user2Id ? "" : "none"
    selectBox.disabled = !leavable
    if (selectBox.disabled) {
        options = ""
        selectBox.innerHTML = options
    } else {
        let s = `<option value=""></option>`
        box.forEach(it => {
            s += `<option value="${it.ownsId}">${it.speciesName}</option>`
        })
        if (s != options) {
            options = s
            selectBox.innerHTML = options
        }
    }
    if (joinable) {
        btnConfirm.style.display = "none"
        btnCancel.style.display = "none"
    } else if (confirmable) {
        btnConfirm.style.display = ""
        btnCancel.style.display = "none"
    } else {
        btnConfirm.style.display = "none"
        btnCancel.style.display = ""
    }
    // if (data.pos) {
    //     if (data.pos == 1) {
    //         user1.textContent = "User ID 1: " + data.userid
    //     } else if (data.pos == 2) {
    //         user2.textContent = "User ID 2: " + data.userid
    //     }
    // }
}

updateUI()

btnJoin.addEventListener('click', e => {
    let req = new XMLHttpRequest()
    req.responseType = 'json'
    req.addEventListener('load', ev => {
        console.log(ev.target.response)
    })
    let url = new URL(document.URL)
    req.open('POST', url.pathname)
    req.setRequestHeader("Content-Type", "application/json;charset=UTF-8")
    req.send(JSON.stringify({type: 'join'}))
})

btnLeave.addEventListener('click', e => {
    let req = new XMLHttpRequest()
    req.responseType = 'json'
    req.addEventListener('load', ev => {
        console.log(ev.target.response)
    })
    let url = new URL(document.URL)
    req.open('POST', url.pathname)
    req.setRequestHeader("Content-Type", "application/json;charset=UTF-8")
    req.send(JSON.stringify({type: 'leave'}))
})

selectBox.addEventListener("input", ev => {
    let stageID = ev.target.value
    if (!reNat.test(stageID)) {
        stageID = ""
    }
    let req = new XMLHttpRequest()
    req.responseType = 'json'
    req.addEventListener('load', ev => {
        console.log(ev.target.response)
    })
    let url = new URL(document.URL)
    req.open('POST', url.pathname)
    req.setRequestHeader("Content-Type", "application/json;charset=UTF-8")
    req.send(JSON.stringify({type: 'stage', stageID: stageID}))
})

btnConfirm.addEventListener('click', ev => {
    let req = new XMLHttpRequest()
    req.responseType = 'json'
    req.addEventListener('load', ev => {
        console.log(ev.target.response)
    })
    let url = new URL(document.URL)
    req.open('POST', url.pathname)
    req.setRequestHeader("Content-Type", "application/json;charset=UTF-8")
    req.send(JSON.stringify({type: 'confirm', value: true}))
})

btnCancel.addEventListener('click', ev => {
    let req = new XMLHttpRequest()
    req.responseType = 'json'
    req.addEventListener('load', ev => {
        console.log(ev.target.response)
    })
    let url = new URL(document.URL)
    req.open('POST', url.pathname)
    req.setRequestHeader("Content-Type", "application/json;charset=UTF-8")
    req.send(JSON.stringify({type: 'confirm', value: false}))
})

let tradePoll = () => {
    let req = new XMLHttpRequest()
    req.responseType = 'json'
    req.addEventListener('load', ev => {
        if (ev.target.status == 404) {
            window.location.replace("/myMon")
        }
        trade = ev.target.response
        joinable = (!trade.user1Id || !trade.user2Id) && trade.user1Id != trade.userid && trade.user2Id != trade.userid
        leavable = trade.user1Id == trade.userid || trade.user2Id == trade.userid
        confirmable = leavable && ((trade.user1Id == trade.userid && !trade.confirm1) || (trade.user2Id == trade.userid && !trade.confirm2))
        cancellable = leavable && !confirmable
        updateUI()
        setTimeout(tradePoll, 1000)
    })
    req.addEventListener('error', ev => {
        console.log(ev.target.response)
        setTimeout(tradePoll, 1000)
    })
    req.addEventListener('abort', ev => {
        console.log(ev.target.response)
        setTimeout(tradePoll, 1000)
    })
    let url = new URL(document.URL)
    req.open('POST', url.pathname)
    req.setRequestHeader("Content-Type", "application/json;charset=UTF-8")
    req.send(JSON.stringify({type: 'tradePoll'}))
}

let boxPoll = () => {
    let req = new XMLHttpRequest()
    req.responseType = 'json'
    req.addEventListener('load', ev => {
        box = ev.target.response
        updateUI()
        setTimeout(boxPoll, 5000)
    })
    req.addEventListener('error', ev => {
        console.log(ev.target.response)
        setTimeout(boxPoll, 5000)
    })
    req.addEventListener('abort', ev => {
        console.log(ev.target.response)
        setTimeout(boxPoll, 5000)
    })
    let url = new URL(document.URL)
    req.open('POST', url.pathname)
    req.setRequestHeader("Content-Type", "application/json;charset=UTF-8")
    req.send(JSON.stringify({type: 'boxPoll'}))
}

tradePoll()
boxPoll()