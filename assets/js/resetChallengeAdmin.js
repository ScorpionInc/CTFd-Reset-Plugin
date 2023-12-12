//Reference Code: ./CTFd/themes/admin/assets/js/pages/statistics.js
//Reference Code: ./CTFd/plugins/resetChallenge/ResetChallengeAPI.py

import "./main";
import "core/utils";
import CTFd from "core/CTFd";
import $ from "jquery";
import echarts from "echarts/dist/echarts-en.common";
import { colorHash } from "core/utils";

//TODO
const graph_configs = {
  "#resets-graph": {
	  data: () =>
      CTFd.fetch("/api/v1/resets").then(function(
        response
      ) {
        return response.json();
      })
  }
};

const createGraphs = () => {
  for (let key in graph_configs) {
    const cfg = graph_configs[key];
const createGraphs = () => {
  for (let key in graph_configs) {
    const cfg = graph_configs[key];

    const $elem = $(key);
    $elem.empty();

    let chart = echarts.init(document.querySelector(key));

    cfg
      .data()
      .then(cfg.format)
      .then(option => {
        chart.setOption(option);
        $(window).on("resize", function() {
          if (chart != null && chart != undefined) {
            chart.resize();
          }
        });
      });
  }
};

function updateGraphs() {
  for (let key in graph_configs) {
    const cfg = graph_configs[key];
    let chart = echarts.init(document.querySelector(key));
    cfg
      .data()
      .then(cfg.format)
      .then(option => {
        chart.setOption(option);
      });
  }
}

$(() => {
  createGraphs();
  setInterval(updateGraphs, 300000);
});
    const $elem = $(key);
    $elem.empty();

    let chart = echarts.init(document.querySelector(key));

    cfg
      .data()
      .then(cfg.format)
      .then(option => {
        chart.setOption(option);
        $(window).on("resize", function() {
          if (chart != null && chart != undefined) {
            chart.resize();
          }
        });
      });
  }
};

function updateGraphs() {
  for (let key in graph_configs) {
    const cfg = graph_configs[key];
    let chart = echarts.init(document.querySelector(key));
    cfg
      .data()
      .then(cfg.format)
      .then(option => {
        chart.setOption(option);
      });
  }
}

$(() => {
  createGraphs();
  setInterval(updateGraphs, 300000);
});