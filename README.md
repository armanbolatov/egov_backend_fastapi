# Gov4c Backend

This is the backend for the top-2 solution on the HackNU 2023 hackathon (Gov4c/Huawei track). It is a REST API written in Python using the FastAPI framework. It uses Gov4c's (Government for Citizens) services to provide a unified API for the frontend (see the [frontend repository](https://github.com/Abyl10/egov_frontend) for more information).

Main features include: send SMS from 1414 (the official SMS service of the government), get the status of the Electronic Government orders, get a person's phone number and personal information from IIN (state ID number), assign a courier to an order, generate and verify one-time password.