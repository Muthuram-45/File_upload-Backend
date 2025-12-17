const fs = require("fs");
const csv = require("csv-parser");

const readCSV = (filePath) => {
  return new Promise((resolve, reject) => {
    let headers = [];
    const data = [];

    fs.createReadStream(filePath)
      .pipe(csv())
      .on("data", (row) => {
        // Extract headers from first row
        if (headers.length === 0) {
          headers = Object.keys(row);
        }
        data.push(row);
      })
      .on("end", () => {
        resolve({ headers, data });
      })
      .on("error", (err) => {
        reject(err);
      });
  });
};

module.exports = readCSV;
