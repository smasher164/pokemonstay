const magenta = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8OnPHfwAIGANHqdc/SQAAAABJRU5ErkJggg=="
const blue = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mOsuvWsHgAGywK7a9uC3wAAAABJRU5ErkJggg=="

let btnJoin = document.querySelector("#btn-join")
let btnLeave = document.querySelector("#btn-leave")
let btnConfirm = document.querySelector("#btn-confirm")
let btnCancel = document.querySelector("#btn-cancel")
let user1 = document.querySelector("#user1")
let user2 = document.querySelector("#user2")
let pokemon1 = document.querySelector("#pokemon1")
let pokemon2 = document.querySelector("#pokemon2")
let tradeimg1 = document.querySelector("#tradeimg1")
let tradeimg2 = document.querySelector("#tradeimg2")
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

let pad = num => num <= 999 ? `00${num}`.slice(-3) : num

let pokeimg = (num, shiny) => {
    if (shiny) {
        return `https://www.serebii.net/Shiny/SM/${pad(num)}.png`
    }
    return `https://www.serebii.net/sunmoon/pokemon/${pad(num)}.png`
}

let gender = {
    0: "Genderless",
    1: "Male",
    2: "Female",
}

let lv = n => {
    if (n == null) {
        return ""
    }
    return "Lv"+n
}

let name = (species, nickname, shiny) => {
    let s = species
    if (nickname) {
        s += "("+nickname+")"
    }
    if (shiny) {
        s += "★"
    }
    return s
}

let updateUI = () => {
    btnJoin.style.display = joinable ? "" : "none"
    btnLeave.style.display = leavable ? "" : "none"
    user1.textContent = trade.userName1 ? `User 1: ${trade.userName1}` : "Waiting for User 1..."
    user2.textContent = trade.userName2 ? `User 2: ${trade.userName2}` : "Waiting for User 2..."
    if(trade.pokemon1 && trade.pokemon1.ownsId != null) {
        pokemon1.textContent = [
            name(trade.pokemon1.species, trade.pokemon1.nickname, trade.pokemon1.shiny),
            gender[trade.pokemon1.gender],
            lv(trade.pokemon1.level)
        ].join("\n")
        tradeimg1.src = pokeimg(trade.pokemon1.number, trade.pokemon1.shiny)
    } else {
        pokemon1.textContent = "No offer"
        tradeimg1.src = magenta
    }
    if(trade.pokemon2 && trade.pokemon2.ownsId != null) {
        pokemon2.textContent = [
            name(trade.pokemon2.species, trade.pokemon2.nickname, trade.pokemon2.shiny),
            gender[trade.pokemon2.gender],
            lv(trade.pokemon2.level)
        ].join("\n")
        tradeimg2.src = pokeimg(trade.pokemon2.number, trade.pokemon2.shiny)
    } else {
        pokemon2.textContent = "No offer"
        tradeimg2.src = blue
    }
    confirm1.textContent = Boolean(trade.confirm1) ? 'Confirmed' : "Not confirmed"
    confirm2.textContent = Boolean(trade.confirm2) ? 'Confirmed' : "Not confirmed"
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
    } else if (leavable) {
        btnConfirm.style.display = "none"
        btnCancel.style.display = ""
    } else {
        btnConfirm.style.display = "none"
        btnCancel.style.display = "none"
    }
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
        setTimeout(boxPoll, 30000)
    })
    req.addEventListener('error', ev => {
        console.log(ev.target.response)
        setTimeout(boxPoll, 30000)
    })
    req.addEventListener('abort', ev => {
        console.log(ev.target.response)
        setTimeout(boxPoll, 30000)
    })
    let url = new URL(document.URL)
    req.open('POST', url.pathname)
    req.setRequestHeader("Content-Type", "application/json;charset=UTF-8")
    req.send(JSON.stringify({type: 'boxPoll'}))
}

tradePoll()
boxPoll()